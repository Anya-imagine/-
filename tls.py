def tls_parser(payload, offset=0, data=None, length=None, options=None):
    """
    Parse TLS handshake message and extract relevant information
    Args:
        payload: The TLS message payload
        offset: Offset in the payload (optional)
        data: Additional data (optional)
        length: Length of the payload (optional)
        options: Additional options (optional)
    """
    try:
        # Check if payload is long enough to contain TLS header
        if len(payload) < 5:
            return None
            
        # TLS Record Layer
        content_type = payload[0]
        version = payload[1:3]
        length = int.from_bytes(payload[3:5], byteorder='big')
        
        # Check if it's a handshake message
        if content_type != 0x16:  # 0x16 is handshake
            return None
            
        # Get TLS version
        tls_version = "Unknown"
        if version == b'\x03\x01':
            tls_version = "TLS 1.0"
        elif version == b'\x03\x02':
            tls_version = "TLS 1.1"
        elif version == b'\x03\x03':
            tls_version = "TLS 1.2"
        elif version == b'\x03\x04':
            tls_version = "TLS 1.3"
            
        # Get handshake message
        if len(payload) < 6:
            return None
            
        handshake_type = payload[5]
        handshake_type_str = "Unknown"
        
        if handshake_type == 1:
            handshake_type_str = "Client Hello"
        elif handshake_type == 2:
            handshake_type_str = "Server Hello"
        elif handshake_type == 11:
            handshake_type_str = "Certificate"
        elif handshake_type == 16:
            handshake_type_str = "Client Key Exchange"
        elif handshake_type == 14:
            handshake_type_str = "Server Key Exchange"
        elif handshake_type == 15:
            handshake_type_str = "Certificate Request"
        elif handshake_type == 20:
            handshake_type_str = "Finished"
            
        # Get cipher suite (only for Client Hello and Server Hello)
        cipher_suite = "Unknown"
        if handshake_type in [1, 2] and len(payload) > 40:
            # Skip handshake header and random bytes
            offset = 6 + 4 + 32  # handshake header + length + random
            if handshake_type == 1:  # Client Hello
                # Skip session ID
                session_id_length = payload[offset]
                offset += 1 + session_id_length
                # Skip cipher suites length
                offset += 2
                # Get first cipher suite
                if len(payload) >= offset + 2:
                    cipher_suite = int.from_bytes(payload[offset:offset+2], byteorder='big')
            elif handshake_type == 2:  # Server Hello
                # Skip session ID
                session_id_length = payload[offset]
                offset += 1 + session_id_length
                # Get cipher suite
                if len(payload) >= offset + 2:
                    cipher_suite = int.from_bytes(payload[offset:offset+2], byteorder='big')
                    
        return {
            'version': tls_version,
            'handshake_type': handshake_type_str,
            'cipher_suite': f"0x{cipher_suite:04x}"
        }
        
    except Exception as e:
        print(f"Error parsing TLS message: {str(e)}")
        return None 
def tls_parser_simple(payload):
    return tls_parser(payload, 0, None, None, None) 
