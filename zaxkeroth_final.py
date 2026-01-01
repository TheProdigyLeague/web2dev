import grpc, json, os, gateway_pb2, gateway_pb2_grpc
def load_validated_session():
    if not os.path.exists("session_validated.json"):
        return None
    with open("session_validated.json", "r") as f:
        cookies = json.load(f)
    return "; ".join([f"{k}={v}" for k, v in cookies.items()])
def run_audit():
    session_str = load_validated_session()
    if not session_str: return
    metadata = (
        ('user-agent', 'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'),
        ('cookie', session_str),
        ('content-type', 'application/grpc'),
        ('te', 'trailers'),
    )
    target_ip = "23.12.69.135:443" 
    credentials = grpc.ssl_channel_credentials()
    channel = grpc.secure_channel(target_ip, credentials)
    stub = gateway_pb2_grpc.QuoteStub(channel)
    try:
        print("[*] Initiating Zaxkeroth secure probe...")
        request_payload = gateway_pb2.ClientRequest(type=1, requestId="audit_init") 
        response = stub.request(request_payload, timeout=15, metadata=metadata)
        print(f"✅ Response Received: {response.msg}")
    except grpc.RpcError as e:
        print(f"❌ gRPC Handshake Failed: {e.code()}")
if __name__ == "__main__":
    run_audit()
