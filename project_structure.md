# DNA Blockchain Access System - Project Structure

```
dna-blockchain-system/
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
│
├── blockchain/
│   ├── __init__.py
│   ├── abci_app.py              # Main ABCI application
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── dna_registry.py      # DNA sample registry
│   │   ├── nft_module.py        # ERC-721 NFT implementation
│   │   ├── access_control.py    # Access control registry
│   │   ├── multisig.py          # Multi-signature logic
│   │   └── zkp_handler.py       # ZKP verification handler
│   ├── config/
│   │   ├── genesis.json         # Tendermint genesis
│   │   └── config.toml          # Tendermint config
│   └── scripts/
│       ├── init_tendermint.sh
│       └── start_node.sh
│
├── encryption/
│   ├── __init__.py
│   ├── aes_crypto.py            # AES-256 encryption utilities
│   └── key_manager.py           # Local key management
│
├── zkp/
│   ├── circuits/
│   │   ├── prove_access_permission.nr
│   │   └── verify_permission.nr
│   ├── python/
│   │   ├── __init__.py
│   │   ├── proof_generator.py   # Generate ZK proofs
│   │   └── proof_verifier.py    # Verify ZK proofs
│   └── scripts/
│       └── build_circuits.sh
│
├── firebase/
│   ├── __init__.py
│   ├── config.json              # Firebase configuration
│   ├── storage_handler.py       # Firebase Storage operations
│   ├── firestore_handler.py     # Firestore operations
│   └── cloud_functions/
│       ├── index.js
│       └── package.json
│
├── api/
│   ├── __init__.py
│   ├── main.py                  # FastAPI application
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── dna_upload.py        # DNA upload endpoints
│   │   ├── access_request.py    # Access request endpoints
│   │   └── nft_operations.py    # NFT operations
│   └── models/
│       ├── __init__.py
│       └── schemas.py           # Pydantic models
│
├── database/
│   ├── __init__.py
│   └── mongodb_handler.py       # MongoDB operations (optional)
│
├── tests/
│   ├── __init__.py
│   ├── test_blockchain.py
│   ├── test_encryption.py
│   ├── test_zkp.py
│   ├── test_api.py
│   └── integration/
│       └── test_full_flow.py
│
└── scripts/
    ├── start_system.sh          # Start entire system
    ├── stop_system.sh           # Stop system
    ├── run_tests.sh             # Run test suite
    └── setup_environment.sh     # Initial setup
```