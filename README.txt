This is just a sample to push the current work

Policy_Setup:
  - A python script that extract index list
  - The extraction depends on the MBs's needs
  - HTTP firewall: Extract the block(s) that contains HTTP version
  - DNS filtering: DoT/DoH. Extract the DNS request name

TLS: We utilize tlslite-ng from the ZKMBs work.
  - It serves as a client
  - It establishes TLS handshake to the remote serve and derives session key and nonce for the TLS ciphertext

AES-GCM: We utilize AES-GCM module
  - This module on input the index list and session key and nonce from TLS. It returns the keystreams and proof tuple

MBs Inspection:
  - On input TLS ciphertext tuple and keystreams, it decrypts the block(s) and identify whether they are policy compliance 

MPC: We adopt MP-SDPZ modules
  - Based on keystreams and proof tuple, client and MBs run this MPC to validate the binding of TLS ciphertext tuple and proof tuple
