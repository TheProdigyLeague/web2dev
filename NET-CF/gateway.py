# Assuming the necessary .proto files (gateway.proto, api.proto) are compiled
# using 'python -m grpc_tools.protoc --proto_path=. --python_out=. --grpc_python_out=. gateway.proto api.proto'

import grpc
import time

# Resolved IP for www.turbotax.com
TARGET_ADDRESS = '23.12.69.135:443'
# SNI is required to bypass Akamai/IronPort resets
SNI_OVERRIDE = 'www.turbotax.com' 

# Import the generated gRPC modules (uncomment when stubs are present)
# import gateway_pb2_grpc
# import gateway_pb2

def grpc_ping_test():
    # Added SNI mapping to bypass TCP resets
    options = [('grpc.ssl_target_name_override', SNI_OVERRIDE)]
    
    try:
        print(f"[*] Attempting secure gRPC connection to {TARGET_ADDRESS}...")
        
        # Using default SSL credentials for the handshake
        credentials = grpc.ssl_channel_credentials()
        
        with grpc.secure_channel(TARGET_ADDRESS, credentials, options=options) as channel:
            # All lines below are now correctly indented with 12 spaces
            stub = gateway_pb2_grpc.QuoteStub(channel)
            
            ping_request = gateway_pb2.ClientRequest(
                type=gateway_pb2.MsgType.Ping,
                requestId=str(int(time.time() * 1000)),
                path="",
                payload=b""
            )
            
            print("[*] Sending Ping request...")
            response = stub.Request(ping_request, timeout=10)
            
            if response.type == gateway_pb2.MsgType.Pong:
                print("✅ gRPC Ping Successful: Service is alive.")
            else:
                print(f"⚠️ Response Received: Type={response.type}, Message={response.msg}")

    except grpc.RpcError as e:
        print(f"❌ gRPC connection failed: {e.code().name} - {e.details()}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    grpc_ping_test()
