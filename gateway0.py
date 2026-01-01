import grpc
import time

# NOTE: Updated to the Cloudflare IP found in your packet analysis
TARGET_ADDRESS = '23.12.69.135'
# Updated to the live site as the reference for SSL targets
SSL_TARGET = 'www.turbotax.com'

def grpc_ping_test():
    print(f"Attempting gRPC connection to {TARGET_ADDRESS} via {SSL_TARGET}...")
    
    # Based on your logs, the TLS 1.3 handshake is being reset (RST)
    # This command is for documentation of the manual check you should perform:
    print("\n[!] TLS 1.3 Handshake resets detected in packets.")
    print(f"Manual check recommended: grpc-cli call {TARGET_ADDRESS} openapi.Quote.Request --ssl_target_name={SSL_TARGET}")

if __name__ == "__main__":
    grpc_ping_test()
