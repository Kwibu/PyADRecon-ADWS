import logging
import socket

import impacket.examples.logger
import impacket.ntlm
import impacket.spnego
import impacket.structure
from Cryptodome.Cipher import ARC4
from impacket.hresult_errors import ERROR_MESSAGES

from .encoder.records.utils import Net7BitInteger


def hexdump(data, length=16):
    def to_ascii(byte):
        if 32 <= byte <= 126:
            return chr(byte)
        else:
            return "."

    def format_line(offset, line_bytes):
        hex_part = " ".join(f"{byte:02X}" for byte in line_bytes)
        ascii_part = "".join(to_ascii(byte) for byte in line_bytes)
        return f"{offset:08X}  {hex_part:<{length*3}}  {ascii_part}"

    lines = []
    for i in range(0, len(data), length):
        line_bytes = data[i : i + length]
        lines.append(format_line(i, line_bytes))

    return "\n".join(lines)


class NNS_pkt(impacket.structure.Structure):
    structure: tuple[tuple[str, str], ...]

    def send(self, sock: socket.socket):
        sock.sendall(self.getData())


class NNS_handshake(NNS_pkt):
    structure = (
        ("message_id", ">B"),
        ("major_version", ">B"),
        ("minor_version", ">B"),
        ("payload_len", ">H-payload"),
        ("payload", ":"),
    )

    # During negotitiate, payload will be the GSSAPI, containing SPNEGO
    # w/ NTLMSSP for NTLM or
    # w/ krb5_blob for the AP REQ)

    # For NTLM
    # NNS Headers
    # |_ Payload ( GSS-API )
    #   |_ SPNEGO ( NegTokenInit )
    #     |_ NTLMSSP

    # For Kerberos
    # NNS Headers
    # |_ Payload ( GSS-API )
    #   |_ SPNEGO ( NegTokenInit )
    #     |_ krb5_blob
    #       |_ Kerberos ( AP REQ )

    ###

    # During challenge, payload will be the GSSAPI, containing SPNEGO
    # w/ NTLMSSP for NTLM or
    # w/ krb5_blob for the AP REQ)

    # For NTLM
    # NNS Headers
    # |_ Payload ( GSS-API, SPNEGO, no GSS-API headers )
    #     |_ NegTokenTarg ( NegTokenResp )
    #       |_ NTLMSSP

    def __init__(
        self, message_id: int, major_version: int, minor_version: int, payload: bytes
    ):
        impacket.structure.Structure.__init__(self)
        self["message_id"] = message_id
        self["major_version"] = major_version
        self["minor_version"] = minor_version
        self["payload"] = payload


class NNS_data(NNS_pkt):
    # NNS data message, used after auth is completed

    structure = (
        ("payload_size", "<L-payload"),
        ("payload", ":"),
    )


class NNS_Signed_payload(impacket.structure.Structure):
    structure = (
        ("signature", ":"),
        ("cipherText", ":"),
    )


class MessageID:
    IN_PROGRESS: int = 0x16
    ERROR: int = 0x15
    DONE: int = 0x14


class NNS:
    """[MS-NNS]: .NET NegotiateStream Protocol

    The .NET NegotiateStream Protocol provides mutually authenticated
    and confidential communication over a TCP connection.

    It defines a framing mechanism used to transfer (GSS-API) security tokens
    between a client and server. It also defines a framing mechanism used
    to transfer signed and/or encrypted application data once the GSS-API
    security context initialization has completed.
    """

    def __init__(
        self,
        socket: socket.socket,
        fqdn: str,
        domain: str,
        username: str,
        password: str | None = None,
        nt: str = "",
        lm: str = "",
        auth_type: str = 'ntlm',
        use_ccache: bool = False,
        spn: str | None = None,
    ):
        self._sock = socket

        self._nt = self._fix_hashes(nt)
        self._lm = self._fix_hashes(lm)

        self._username = username
        self._password = password

        self._domain = domain
        self._fqdn = fqdn
        
        # Authentication type and Kerberos parameters
        self._auth_type = auth_type
        self._use_ccache = use_ccache
        # Default to HTTP SPN (more commonly registered than WSMAN)
        self._spn = spn or f"HTTP/{fqdn}"
        self._gssapi_ctx = None  # Store GSSAPI context for wrap/unwrap

        self._session_key: bytes = b""
        self._flags: int = -1
        self._sequence: int = 0

    def _fix_hashes(self, hash: str | bytes) -> bytes | str:
        """fixes up hash if present into bytes and
        ensures length is 32.

        If no hash is present, returns empty bytes

        Args:
            hash (str | bytes): nt or lm hash

        Returns:
            bytes: bytes version
        """

        if not hash:
            return ""

        if len(hash) % 2:
            hash = hash.zfill(32)

        return bytes.fromhex(hash) if isinstance(hash, str) else hash

    def seal(self, data: bytes) -> tuple[bytes, bytes]:
        """seals data with the current context

        Args:
            data (bytes): bytes to seal

        Returns:
            tuple[bytes, bytes]: output_data, signature
        """
        
        # Use GSSAPI wrap for Kerberos
        if self._auth_type == 'kerberos' and self._gssapi_ctx:
            try:
                wrapped = self._gssapi_ctx.wrap(data, encrypt=True)
                # For GSSAPI, the wrapped message includes both encrypted data and signature
                # We need to split it for NNS protocol compatibility
                # Use first 16 bytes as signature, rest as ciphertext
                if len(wrapped.message) > 16:
                    sig = wrapped.message[:16]
                    output = wrapped.message[16:]
                else:
                    sig = wrapped.message
                    output = data  # Fallback
                return output, sig
            except Exception as e:
                logging.warning(f"GSSAPI wrap failed, using plaintext: {e}")
                return data, b'\x00' * 16

        # Use NTLM SEAL for NTLM authentication
        server = bool(
            self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        )

        output, sig = impacket.ntlm.SEAL(
            self._flags,
            self._server_signing_key if server else self._client_signing_key,
            self._server_sealing_key if server else self._client_sealing_key,
            data,
            data,
            self._sequence,
            self._server_sealing_handle if server else self._client_sealing_handle,
        )

        return output, sig.getData()

    def recv(self, _: int = 0) -> bytes:
        """Recive an NNS packet and return the entire
        decrypted contents.

        The paramiter is used to allow interoperability with socket.socket.recv.
        Does not respect any passed buffer sizes.

        Args:
            _ (int, optional): For interoperability with socket.socket. Defaults to 0.

        Returns:
            bytes: unsealed nns message
        """
        first_pkt = self._recv()

        # if it isnt an envelope, throw it back
        if first_pkt[0] != 0x06:
            return first_pkt

        nmfsize, nmflenlen = Net7BitInteger.decode7bit(first_pkt[1:])

        # its all just one packet
        if nmfsize < 0xFC30:
            return first_pkt

        # otherwise, we have a multi part message
        pkt = first_pkt
        nmfsize -= len(first_pkt[nmflenlen:])

        while nmfsize > 0:
            thisFragment = self._recv()

            pkt += thisFragment
            nmfsize -= len(thisFragment)

        return pkt

    def _recv(self, _: int = 0) -> bytes:
        """Recive an NNS packet and return the entire
        decrypted contents.

        The paramiter is used to allow interoperability with socket.socket.recv.
        Does not respect any passed buffer sizes.
        """
        nns_data = NNS_data()
        size = int.from_bytes(self._sock.recv(4), "little")

        payload = b""
        while len(payload) != size:
            payload += self._sock.recv(size - len(payload))
        nns_data["payload"] = payload

        # Use GSSAPI unwrap for Kerberos
        if self._auth_type == 'kerberos' and self._gssapi_ctx:
            try:
                # For GSSAPI, reconstruct the wrapped message
                # Signature (16 bytes) + ciphertext
                wrapped_message = nns_data["payload"]
                unwrapped = self._gssapi_ctx.unwrap(wrapped_message)
                return unwrapped.message
            except Exception as e:
                logging.warning(f"GSSAPI unwrap failed, using plaintext: {e}")
                # Try to extract payload without decryption
                if len(nns_data["payload"]) > 16:
                    return nns_data["payload"][16:]
                return nns_data["payload"]
        
        # Use NTLM SEAL for NTLM authentication
        nns_signed_payload = NNS_Signed_payload()
        nns_signed_payload["signature"] = nns_data["payload"][0:16]
        nns_signed_payload["cipherText"] = nns_data["payload"][16:]

        clearText, sig = self.seal(nns_signed_payload["cipherText"])
        return clearText

    def sendall(self, data: bytes):
        """send to server in NTLM/Kerberos sealed NNS data packet via tcp socket.

        Args:
            data (bytes): utf-16le encoded payload data
        """
        
        # Use GSSAPI wrap for Kerberos
        if self._auth_type == 'kerberos' and self._gssapi_ctx:
            try:
                wrapped = self._gssapi_ctx.wrap(data, encrypt=True)
                # Send wrapped message as NNS data packet
                pkt = NNS_data()
                pkt["payload"] = wrapped.message
                self._sock.sendall(pkt.getData())
                logging.debug(f"Sent {len(data)} bytes (wrapped: {len(wrapped.message)} bytes) via GSSAPI")
                return
            except Exception as e:
                logging.error(f"GSSAPI wrap failed: {e}")
                raise
        
        # Use NTLM SEAL for NTLM authentication
        cipherText, sig = impacket.ntlm.SEAL(
            self._flags,
            self._client_signing_key,
            self._client_sealing_key,
            data,
            data,
            self._sequence,
            self._client_sealing_handle,
        )

        # build the NNS data packet to use
        pkt = NNS_data()

        # then we build the payload, which is the signature prepended
        # on the actual ciphertext.  This goes in the payload of
        # the NNS data packet
        payload = NNS_Signed_payload()
        payload["signature"] = sig
        payload["cipherText"] = cipherText
        pkt["payload"] = payload.getData()

        self._sock.sendall(pkt.getData())

        # and we increment the sequence number after sending
        self._sequence += 1

    def auth_ntlm(self) -> None:
        """Authenticate to the dest with NTLMV2 authentication"""

        # Initial negotiation sent from client
        NegTokenInit: impacket.spnego.SPNEGO_NegTokenInit
        NtlmSSP_nego: impacket.ntlm.NTLMAuthNegotiate

        # Generate a NTLMSSP
        NtlmSSP_nego = impacket.ntlm.getNTLMSSPType1(
            workstation="",  # These fields don't get populated for some reason
            domain="",  # These fields don't get populated for some reason
            signingRequired=True,  # TODO: Somehow determine this; can we send a Negotiate Protocol Request and derive this dynamically?
            use_ntlmv2=True,  # TODO: See above comment
        )

        # Generate the NegTokenInit
        # Impacket has this inherit from GSSAPI, so we will also have the OID and other headers :D
        NegTokenInit = impacket.spnego.SPNEGO_NegTokenInit()
        NegTokenInit["MechTypes"] = [
            impacket.spnego.TypesMech[
                "NTLMSSP - Microsoft NTLM Security Support Provider"
            ],
            impacket.spnego.TypesMech["MS KRB5 - Microsoft Kerberos 5"],
            impacket.spnego.TypesMech["KRB5 - Kerberos 5"],
            impacket.spnego.TypesMech[
                "NEGOEX - SPNEGO Extended Negotiation Security Mechanism"
            ],
        ]
        NegTokenInit["MechToken"] = NtlmSSP_nego.getData()

        # Fit it all into an NNS NTLMSSP_NEGOTIATE Message
        # Begin authentication ( NTLMSSP_NEGOTIATE )
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=NegTokenInit.getData(),
        ).send(self._sock)

        # Response with challenge from server
        NNS_msg_chall: NNS_handshake
        s_NegTokenTarg: impacket.spnego.SPNEGO_NegTokenResp
        NTLMSSP_chall: impacket.ntlm.NTLMAuthChallenge

        # Receive the NNS NTLMSSP_Challenge
        NNS_msg_chall = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        # Extract the NegTokenResp ( NegTokenTarg )
        # Note: Potentially consider SupportedMech from s_NegTokenTarg for determining stuff like signing?
        s_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp(NNS_msg_chall["payload"])

        # Create an NtlmAuthChallenge from the NTLMSSP ( ResponseToken )
        NTLMSSP_chall = impacket.ntlm.NTLMAuthChallenge(s_NegTokenTarg["ResponseToken"])

        # TODO: see if this is relevant https://github.com/fortra/impacket/blob/15eff8805116007cfb59332a64194a5b9c8bcf25/impacket/smb3.py#L1015
        # if NTLMSSP_chall[ 'TargetInfoFields_len' ] > 0:
        #     av_pairs   = impacket.ntlm.AV_PAIRS( NTLMSSP_chall[ 'TargetInfoFields' ][ :NTLMSSP_chall[ 'TargetInfoFields_len' ] ] )
        #     if av_pairs[ impacket.ntlm.NTLMSSP_AV_HOSTNAME ] is not None:
        #         print( "TODO AV PAIRS IDK IF ITS RELEVANT" )

        # Response with authentication from client
        c_NegTokenTarg: impacket.spnego.SPNEGO_NegTokenResp
        NTLMSSP_chall_resp: impacket.ntlm.NTLMAuthChallengeResponse

        # Create the NTLMSSP challenge response
        # If password is used, then the lm and nt hashes must be pass
        # an empty str, NOT, empty byte str.......
        NTLMSSP_chall_resp, self._session_key = impacket.ntlm.getNTLMSSPType3(
            type1=NtlmSSP_nego,
            type2=NTLMSSP_chall.getData(),
            user=self._username,
            password=self._password,
            domain=self._domain,
            lmhash=self._lm,
            nthash=self._nt,
        )

        # set up info for crypto
        self._flags = NTLMSSP_chall_resp["flags"]
        self._sequence = 0

        if self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            logging.debug("We are doing extended ntlm security")
            self._client_signing_key = impacket.ntlm.SIGNKEY(
                self._flags, self._session_key
            )
            self._server_signing_key = impacket.ntlm.SIGNKEY(
                self._flags, self._session_key, "Server"
            )
            self._client_sealing_key = impacket.ntlm.SEALKEY(
                self._flags, self._session_key
            )
            self._server_sealing_key = impacket.ntlm.SEALKEY(
                self._flags, self._session_key, "Server"
            )

            # prepare keys to handle states
            cipher1 = ARC4.new(self._client_sealing_key)
            self._client_sealing_handle = cipher1.encrypt
            cipher2 = ARC4.new(self._server_sealing_key)
            self._server_sealing_handle = cipher2.encrypt

        else:
            logging.debug("We are doing basic ntlm auth")
            # same key for both ways
            self._client_signing_key = self._session_key
            self._server_signing_key = self._session_key
            self._client_sealing_key = self._session_key
            self._server_sealing_key = self._session_key
            cipher = ARC4.new(self._client_sealing_key)
            self._client_sealing_handle = cipher.encrypt
            self._server_sealing_handle = cipher.encrypt

        # Fit the challenge response into the ResponseToken of our NegTokenTarg
        c_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp()
        c_NegTokenTarg["ResponseToken"] = NTLMSSP_chall_resp.getData()

        # Fit our challenge response into an NNS message
        # Send the NTLMSSP_AUTH ( challenge response )
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=c_NegTokenTarg.getData(),
        ).send(self._sock)

        # Response from server ending handshake
        NNS_msg_done: NNS_handshake

        # Check for success
        NNS_msg_done = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        # check for errors
        if NNS_msg_done["message_id"] == 0x15:
            err_type, err_msg = ERROR_MESSAGES[
                int.from_bytes(NNS_msg_done["payload"], "big")
            ]
            raise SystemExit(f"[-] NTLM Auth Failed with error {err_type} {err_msg}")

    def auth_kerberos(self) -> None:
        """Authenticate using Kerberos via GSSAPI"""
        import sys
        import base64
        
        # Import platform-specific GSSAPI
        try:
            if sys.platform == 'win32':
                import winkerberos as kerberos
                use_winkerberos = True
            else:
                import gssapi
                use_winkerberos = False
        except ImportError as e:
            raise ImportError(
                f"Kerberos libraries not installed: {e}\n"
                "Linux: pip install gssapi\n"
                "Windows: pip install winkerberos"
            )
        
        logging.info(f"Using SPN: {self._spn}")
        logging.debug(f"Starting Kerberos authentication to {self._spn}")
        
        # Generate AP_REQ token using GSSAPI
        if use_winkerberos:
            # Windows implementation using winkerberos
            try:
                result, ctx = kerberos.authGSSClientInit(self._spn)
                if result < 0:
                    raise Exception("Failed to initialize Kerberos context")
                
                result = kerberos.authGSSClientStep(ctx, "")
                if result < 0:
                    raise Exception("Kerberos authentication step failed")
                
                ap_req_token = kerberos.authGSSClientResponse(ctx)
                ap_req_bytes = base64.b64decode(ap_req_token)
                
                logging.debug(f"Generated Kerberos AP_REQ token ({len(ap_req_bytes)} bytes)")
            except Exception as e:
                raise Exception(f"Windows Kerberos authentication failed: {e}")
        else:
            # Linux implementation using gssapi
            try:
                # Convert SPN from Windows format (HTTP/hostname) to GSSAPI format (HTTP@hostname)
                gssapi_spn = self._spn.replace('/', '@')
                logging.debug(f"Converted SPN to GSSAPI format: {gssapi_spn}")
                
                service = gssapi.Name(gssapi_spn, gssapi.NameType.hostbased_service)
                
                # Create credentials (from ccache or password)
                creds = None
                if not self._use_ccache and self._password:
                    # Try to acquire credentials with password
                    try:
                        name = gssapi.Name(f"{self._username}@{self._domain.upper()}",
                                         gssapi.NameType.user)
                        creds = gssapi.raw.acquire_cred_with_password(
                            name, self._password.encode(), usage='initiate'
                        ).creds
                        logging.debug("Acquired Kerberos credentials with password")
                    except AttributeError:
                        # acquire_cred_with_password not available in this gssapi version
                        logging.warning("Password-based Kerberos auth not supported, using ccache")
                        creds = None
                else:
                    logging.debug("Using Kerberos credential cache")
                
                # Create GSSAPI context with encryption and integrity flags
                ctx = gssapi.SecurityContext(
                    name=service,
                    creds=creds,
                    usage='initiate',
                    flags=[gssapi.RequirementFlag.confidentiality, gssapi.RequirementFlag.integrity]
                )
                ap_req_bytes = ctx.step()
                
                # Save context for wrap/unwrap operations
                self._gssapi_ctx = ctx
                
                logging.debug(f"Generated Kerberos AP_REQ token ({len(ap_req_bytes)} bytes)")
                logging.info(f"GSSAPI context created (complete={ctx.complete}, flags={ctx.actual_flags})")
                
                # Extract session key from context (for debugging/logging only)
                try:
                    self._session_key = bytes(ctx.session_key)
                    logging.debug(f"Extracted session key ({len(self._session_key)} bytes)")
                except Exception as e:
                    logging.debug(f"Could not extract session key (not needed for GSSAPI wrap/unwrap): {e}")
                    self._session_key = None
            except Exception as e:
                raise Exception(f"Linux Kerberos authentication failed: {e}")
        
        # Wrap AP_REQ in SPNEGO NegTokenInit
        NegTokenInit = impacket.spnego.SPNEGO_NegTokenInit()
        NegTokenInit["MechTypes"] = [
            impacket.spnego.TypesMech["MS KRB5 - Microsoft Kerberos 5"],
            impacket.spnego.TypesMech["KRB5 - Kerberos 5"],
        ]
        NegTokenInit["MechToken"] = ap_req_bytes
        
        # Send initial auth request
        logging.debug("Sending Kerberos NegTokenInit")
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=NegTokenInit.getData(),
        ).send(self._sock)
        
        # Receive server response
        NNS_msg_resp = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )
        
        logging.debug(f"Received server response (message_id: {hex(NNS_msg_resp['message_id'])})")
        
        # Check for errors
        if NNS_msg_resp["message_id"] == MessageID.ERROR:
            err_type, err_msg = ERROR_MESSAGES[
                int.from_bytes(NNS_msg_resp["payload"], "big")
            ]
            raise SystemExit(f"[-] Kerberos Auth Failed with error {err_type} {err_msg}")
        
        # Process server response to complete GSSAPI context  
        if not use_winkerberos and hasattr(self, '_gssapi_ctx'):
            # Complete the context with server's response if available
            if NNS_msg_resp["payload"] and len(NNS_msg_resp["payload"]) > 0:
                try:
                    # Parse SPNEGO response
                    spnego_resp = impacket.spnego.SPNEGO_NegTokenResp(NNS_msg_resp["payload"])
                    if spnego_resp["ResponseToken"]:
                        # Process the AP_REP to complete context
                        self._gssapi_ctx.step(spnego_resp["ResponseToken"])
                        logging.debug(f"GSSAPI context complete: {self._gssapi_ctx.complete}")
                        
                        # Now try to extract session key again
                        if self._gssapi_ctx.complete:
                            try:
                                self._session_key = bytes(self._gssapi_ctx.session_key)
                                logging.info(f"Extracted session key after context completion ({len(self._session_key)} bytes)")
                            except Exception as e:
                                logging.debug(f"Still cannot extract session key: {e}")
                except Exception as e:
                    logging.debug(f"Could not process server GSSAPI response: {e}")
        
        # For Kerberos, we use GSSAPI wrap/unwrap - no manual key setup needed
        # Just initialize flags and sequence for compatibility
        self._flags = 0
        self._sequence = 0
        
        # Initialize dummy keys for NTLM compatibility (unused with Kerberos)
        if not hasattr(self, '_client_signing_key'):
            self._client_signing_key = b'\x00' * 16
            self._server_signing_key = b'\x00' * 16
            self._client_sealing_key = b'\x00' * 16
            self._server_sealing_key = b'\x00' * 16
            
            from Cryptodome.Cipher import ARC4
            cipher = ARC4.new(self._client_sealing_key)
            self._client_sealing_handle = cipher.encrypt
            self._server_sealing_handle = cipher.encrypt
        
        logging.info("✅ Kerberos authentication successful (using GSSAPI wrap/unwrap)")

