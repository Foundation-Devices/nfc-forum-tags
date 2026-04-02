# nfc-forum-tags

`#![no_std]` Rust implementation of NFC Forum Tag Type operations.

This crate provides the command protocol, memory model, and NDEF access procedures for NFC Forum tags. It sits between the ISO 14443-3A activation layer and NDEF message parsing:

```
iso14443  (activation)  -->  nfc-forum-tags  (tag operations)  -->  ndef  (message parsing)
```

No dependency on either crate — raw `&[u8]` at both boundaries.

## Functionalities

### Type 2 Tag (T2TOP 1.1)

- **Commands**: READ (0x30), WRITE (0xA2), SECTOR SELECT (0xC2)
- **Capability Container**: parsing, validation, version checking, access conditions
- **TLV blocks**: NULL, Lock Control, Memory Control, NDEF Message, Proprietary, Terminator
- **Memory layout**: static (64 bytes) and dynamic (multi-sector) structures, lock/reserved area tracking
- **NDEF operations**: detection, read, and write procedures via `T2TReader`

## Usage

Implement the `T2TTransceiver` trait for your hardware, then use `T2TReader` to interact with the tag:

```rust
use nfc_forum_tags::type2::{T2TTransceiver, T2TReader};

// After ISO 14443-3A activation with a Type 2 Tag...
let mut reader = T2TReader::new(&mut my_transceiver);

// Read the Capability Container
let cc = reader.read_cc()?;

// Read NDEF message bytes
let ndef_bytes = reader.read_ndef()?;
// Pass to ndef crate: ndef::Message::try_from(&*ndef_bytes)

// Write NDEF message bytes
// let ndef_bytes = ndef_message.to_vec();
reader.write_ndef(&ndef_bytes)?;
```

Lower-level access is also available:

```rust
use nfc_forum_tags::type2::Command;

// Build commands manually
let cmd = Command::Read { block_no: 0x04 };
let wire_bytes = cmd.to_bytes(); // [0x30, 0x04] — CRC added by transceiver

// Parse responses
let answer = cmd.parse_answer(&response_bytes)?;
```

## Features

| Feature | Description |
|---------|-------------|
| *(default)* | `no_std` with `heapless` fixed-capacity buffers |
| `alloc` | Use `Vec` instead of `heapless::Vec` |
| `std` | Implies `alloc` |

## License

GPL-3.0-or-later
