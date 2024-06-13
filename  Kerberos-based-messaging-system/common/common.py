import struct


class ProtocolHandler:

    def encode_request(self, device_uuid, version, request_type, payload=None):
        if payload is None:
            payload_size = 0
            header = struct.pack('<16sBHH', device_uuid, version, request_type, payload_size)
            return header
        else:
            payload_size = len(payload)
            header = struct.pack('<16sBHH', device_uuid, version, request_type, payload_size)
            return header + payload

    def decode_request(self, request_data):
        header_size = struct.calcsize('<16sBHH')
        header = struct.unpack('<16sBHH', request_data[:header_size])
        device_uuid, version, request_code, payload_size = header
        payload = request_data[header_size:header_size + payload_size]
        return {
            'device_uuid': device_uuid,
            'version': version,
            'request_code': request_code,
            'payload_size': payload_size,
            'payload': payload
        }

    def encode_response(self, version, response_code, payload=None):
        if payload is None:
            payload_size = 0
            header = struct.pack('BHH', version, response_code, payload_size)
            return header
        else:
            payload_size = len(payload)
            header = struct.pack('BHH', version, response_code, payload_size)
            return header + payload

    def decode_response(self, response_data):
        header_size = struct.calcsize('BHH')
        header = struct.unpack('BHH', response_data[:header_size])
        version, request_code, payload_size = header
        payload = response_data[header_size:header_size + payload_size]
        return {
            'version': version,
            'response_code': request_code,
            'payload_size': payload_size,
            'payload': payload
        }