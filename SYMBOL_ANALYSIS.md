# MCPE 1.1.5 Android client — verified dynamic symbol inventory

**Input:** user-supplied `libminecraftpe.so`, SHA-256
`3eed76a1659e562bf7a1e5efc6119f179c312d3a46b8ce68454b486ba5ed7ddf`.

**Direct inspection:** ELF32 ARM EABI5, 37,980,728 bytes. `.dynsym` has
63,478 entries. SQLite index contains 63,472 *named* symbols: 55,008 FUNC,
8,458 OBJECT and 6 NOTYPE. Of FUNC, 54,609 are defined in the library. This
is exported dynamic symbol metadata, **not decompiled pseudocode**.

## Exact function entries to investigate first

The addresses below come from `readelf --dyn-syms` and `c++filt` on the uploaded
binary. For ARM Thumb symbols, the lowest address bit may encode Thumb mode;
Ghidra code addresses may display with that bit cleared.

| Research question | Demangled exported symbol | ELF symbol value |
|---|---|---|
| Hotbar content wire layout | `ContainerSetContentPacket::read(BinaryStream&)` | `0x0134e5a9` |
| Hotbar content client behavior | `LegacyClientNetworkHandler::handle(NetworkIdentifier const&, ContainerSetContentPacket const&)` | `0x00d0ae2d` |
| Slot packet wire layout | `ContainerSetSlotPacket::read(BinaryStream&)` | `0x00d40347` |
| Slot packet client behavior | `LegacyClientNetworkHandler::handle(NetworkIdentifier const&, ContainerSetSlotPacket const&)` | `0x00d0b281` |
| Held-item reader | `MobEquipmentPacket::read(BinaryStream&)` | `0x00d404e3` |
| Held-item client handler | `LegacyClientNetworkHandler::handle(NetworkIdentifier const&, MobEquipmentPacket const&)` | `0x00d0a4cb` |
| Block-update reader | `UpdateBlockPacket::read(BinaryStream&)` | `0x0134d757` |
| Block-update client handler | `LegacyClientNetworkHandler::handle(NetworkIdentifier const&, UpdateBlockPacket const&)` | `0x00d0a1d5` |
| Breaking-effects reader | `LevelEventPacket::read(BinaryStream&)` | `0x0134dc3d` |
| Breaking-effects client handler | `ClientNetworkHandler::handle(NetworkIdentifier const&, LevelEventPacket const&)` | `0x00d050c9` |
| Client rendering of level events | `LevelRendererPlayer::levelEvent(LevelEvent, Vec3 const&, int)` | `0x00e7ee81` |
| Player-action reader | `PlayerActionPacket::read(BinaryStream&)` | `0x00d405f3` |
| Integrated server action handler | `ServerNetworkHandler::handle(NetworkIdentifier const&, PlayerActionPacket const&)` | `0x013d7065` |
| Chunk packet reader | `FullChunkDataPacket::read(BinaryStream&)` | `0x0134eebd` |
| Chunk client handler | `LegacyClientNetworkHandler::handle(NetworkIdentifier const&, FullChunkDataPacket const&)` | `0x00d0ba29` |
| Shared world mutation | `BlockSource::setBlockAndData(BlockPos const&, FullBlock, int, Entity*, std::unique_ptr<BlockEntity, std::default_delete<BlockEntity> >)` | `0x01701675` |

**Notable finding:** This Android library also exports `ServerNetworkHandler`
functions, including the player-action handler. These are useful to investigate
the client's bundled integrated/server-side behavior, but their presence alone
does not prove dedicated-server behavior is identical.

## What the agent should do in Ghidra

1. Import the matching `.so` and let Ghidra finish auto-analysis.
2. Search functions by demangled symbol names in the list above; account for
   Thumb-bit address notation.
3. Start with the individual packet `read`/`write` functions, then their
   `LegacyClientNetworkHandler` consumers, and compare with the current
   LegacyPE-Server packet encoders.
4. Create compact evidence reports with bytes/fields/conditions and confidence;
   preserve original binary and raw decompilation exports privately.
5. Independently validate each suspected bug using real Android and Windows
   clients before declaring behavioral parity.

## Useful local queries

```bash
python3 tools/symbol_index.py --db symbols.sqlite stats
python3 tools/symbol_index.py --db symbols.sqlite search 'ContainerSetContentPacket'
python3 tools/symbol_index.py --db symbols.sqlite search 'UpdateBlockPacket'
python3 tools/symbol_index.py --db symbols.sqlite search 'ServerNetworkHandler::handle' --limit 50
python3 tools/symbol_index.py --db symbols.sqlite show 0134d757
```

Do not confuse **exported function discovery** with full machine-code function
coverage. Unexported/inlined code requires Ghidra's function discovery and
manual analysis. This report deliberately contains no raw proprietary code.
