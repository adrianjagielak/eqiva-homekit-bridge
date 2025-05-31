// eqiva-homekit-bridge.ts
// -----------------------------------------------------------------------------
// A single‑file TypeScript re‑implementation of the essential parts of the
// open‑source "keyble" library, wired up to HAP‑nodejs so the eQ‑3/eqiva
// Bluetooth Smart Lock appears as a native HomeKit accessory.
// The file is meant to be executed with ts-node *or* compiled with tsc and
// started with Node >= 18 on an Ubuntu / Raspberry Pi host.
// -----------------------------------------------------------------------------

// ─────────────────────────────────────────────────────────────────────────────
// CONFIGURATION (fill in your own values here)
// ─────────────────────────────────────────────────────────────────────────────

const MAC_ADDRESS = '12:34:56:ab:cd:ef'; // Change to the value returned from keyble-registeruser
const USER_ID = 123; // Change to the value returned from keyble-registeruser
const USER_KEY_HEX = '00112233445566778899aabbccddeeff'; // Change to the value returned from keyble-registeruser

const HOMEKIT_ACCESSORY_USERNAME = '00:11:22:33:44:55'; // Change to a random MAC address
const HOMEKIT_ACCESSORY_PIN = '123-45-678'; // Change to a random 8 digit PIN

// ─────────────────────────────────────────────────────────────────────────────

// HomeKit accessory names + constants:
const ACCESSORY_NAME     = 'Eqiva Smart Lock';
const ACCESSORY_MANUFACTURER = 'Eqiva';
const ACCESSORY_MODEL    = 'eQ-3 Bluetooth Smart Lock';
const ACCESSORY_SERIAL   = '1234567890';

// ─────────────────────────────────────────────────────────────────────────────



import {
  createBluetooth,
  Bluetooth,
  Adapter,
  Device,
  GattServer,
  GattService,
  GattCharacteristic,
} from 'node-ble';
import {
  Accessory,
  Service,
  Characteristic,
  CharacteristicEventTypes,
  uuid as hapUUID,
  Categories,
} from 'hap-nodejs';
import { createCipheriv, createDecipheriv } from 'crypto';
import { EventEmitter } from 'events';


// BLE Service + Characteristic UUIDs (standard for Eqiva “keyble”):
const LOCK_SERVICE_UUID  = '58e06900-15d8-11e6-b737-0002a5d5c51b';
const WRITE_CHAR_UUID    = '3141dd40-15db-11e6-a24b-0002a5d5c51b';
const NOTIFY_CHAR_UUID   = '359d4820-15db-11e6-82bd-0002a5d5c51b';

// HomeKit state constants:
const HK_LOCK_CURRENT_STATE = {
  UNSECURED: 0,    // fully unlocked
  SECURED: 1,      // fully locked
  JAMMED: 2,       // jammed
  UNKNOWN: 3,      // unknown
};
const HK_LOCK_TARGET_STATE = {
  UNSECURED: 0,   // unlock
  SECURED: 1,     // lock
};

// BLE messages / framing
// keyble message structure (16-byte blocks, AES CBC, no padding):
//   [CRC16 over payload(2 bytes)] + [user_id (1)] + [cmd_id (1)] + [seq (1)] + [payload bytes…]
//   then pad to 16 bytes with zeros. Then encrypt with AES-CBC using IV=all-zero.
//
// We will keep a rolling sequence counter (0…255).
// For “lock” command, cmd_id = 0x01; for “unlock” cmd_id = 0x02; for “status” cmd_id = 0x04.
//
// The lock returns notifications with the same framing: we decrypt and parse out
//   status info (lock state, battery level, etc.).
//
// These constants come straight from keyble’s message_types.js:
enum CommandID {
  GET_STATUS      = 0x04,
  LOCK_DOOR       = 0x01,
  UNLOCK_DOOR     = 0x02,
  // (It may also support “T O G G L E” as 0x07, but we can issue lock/unlock explicitly.)
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITY FUNCTIONS: CRC16, AES ENCRYPT/DECRYPT, BUFFER FRAMING
// ─────────────────────────────────────────────────────────────────────────────

// 1) CRC16-IBM (XModem) — same CRC16 used by keyble.
function crc16Xmodem(buf: Buffer): number {
  let crc = 0x0000;
  for (let b of buf) {
    crc ^= (b << 8);
    for (let i = 0; i < 8; i++) {
      if (crc & 0x8000) {
        crc = ((crc << 1) ^ 0x1021) & 0xffff;
      } else {
        crc = (crc << 1) & 0xffff;
      }
    }
  }
  return crc & 0xffff;
}

// 2) Build a 16-byte AES frame for a command:
let seqCounter = 0;
function buildCommandPacket(cmdId: CommandID, payload: Buffer = Buffer.alloc(0)): Buffer {
  // [CRC16(2 bytes)] [USER_ID (1)] [CMD_ID (1)] [SEQ (1)] [PAYLOAD…] [PAD…]
  // Compute base (without CRC16):
  const header = Buffer.alloc(4);
  header.writeUInt8(USER_ID & 0xff, 0);        // offset 0 (we’ll write CRC16 later)
  header.writeUInt8(cmdId & 0xff, 1);          // offset 1
  header.writeUInt8(seqCounter & 0xff, 2);     // offset 2
  header.writeUInt8(payload.length & 0xff, 3); // offset 3 (payload length)
  seqCounter = (seqCounter + 1) & 0xff;

  // Combine [header] + [payload] (but we’ll insert CRC16 bytes before header)
  const combined = Buffer.concat([Buffer.alloc(2), header, payload]);
  const crc = crc16Xmodem(combined.slice(2)); // compute over header+payload
  combined.writeUInt16LE(crc, 0);            // write CRC16 into first 2 bytes

  // Pad to 16-byte multiple (block size = 16)
  if (combined.length < 16) {
    return Buffer.concat([combined, Buffer.alloc(16 - combined.length, 0x00)]);
  } else if (combined.length > 16) {
    throw new Error(`Payload too large: ${combined.length} bytes (max 14)`);
  }
  return combined;
}

// 3) AES-128-CBC Encryption / Decryption (IV = 16 zero bytes, no padding)
const AES_KEY = Buffer.from(USER_KEY_HEX, 'hex');
const AES_IV  = Buffer.alloc(16, 0x00);

function aesEncrypt(plain: Buffer): Buffer {
  const cipher = createCipheriv('aes-128-cbc', AES_KEY, AES_IV);
  cipher.setAutoPadding(false);
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
  return encrypted;
}

function aesDecrypt(encrypted: Buffer): Buffer {
  const decipher = createDecipheriv('aes-128-cbc', AES_KEY, AES_IV);
  decipher.setAutoPadding(false);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted;
}

// 4) Parse a decrypted 16-byte response into { cmdId, seq, payload, rawStatus… }
interface DecryptedFrame {
  cmdId: number;
  seq: number;
  payload: Buffer;
  raw: Buffer;
}
function parseResponseFrame(frame: Buffer): DecryptedFrame {
  // Frame layout after decryption (16 bytes):
  // [CRC16 (2)] [USER_ID (1)] [CMD_ID (1)] [SEQ (1)] [LEN (1)] [PAYLOAD…] [PAD…]
  const crcRecvd = frame.readUInt16LE(0);
  const bufForCRC = frame.slice(2); // from USER_ID onward
  const crcCalc = crc16Xmodem(bufForCRC);
  if (crcRecvd !== crcCalc) {
    console.warn(`⚠️ CRC mismatch: recvd 0x${crcRecvd.toString(16)}, calc 0x${crcCalc.toString(16)}`);
  }
  const userId = frame.readUInt8(2);
  const cmdId  = frame.readUInt8(3);
  const seq    = frame.readUInt8(4);
  const len    = frame.readUInt8(5);
  const payload = frame.slice(6, 6 + len);
  return { cmdId, seq, payload, raw: frame };
}

// ─────────────────────────────────────────────────────────────────────────────
// BLE + HomeKit “Glue” Class
// ─────────────────────────────────────────────────────────────────────────────

class EqivaLock extends EventEmitter {
  private bluetooth: Bluetooth;
  public destroy: () => void;
  private adapter!: Adapter;
  private device!: Device;
  private gattServer!: GattServer;
  private writeChar!: GattCharacteristic;
  private notifyChar!: GattCharacteristic;
  private isConnected = false;
  private reconnectTimeout?: NodeJS.Timeout;

  constructor() {
    super();
    // Create a Bluetooth session (node-ble)
    const { bluetooth, destroy } = createBluetooth();
    this.bluetooth = bluetooth;
    this.destroy = destroy;
  }

  // Discover, connect, and set up notifications:
  public async start(): Promise<void> {
    console.log('[BLE] Initializing adapter…');
    this.adapter = await this.bluetooth.defaultAdapter();

    // Continuously try to connect:
    await this.attemptConnectLoop();
  }

  // Try to connect, and if fails, retry after a delay:
  private async attemptConnectLoop(): Promise<void> {
    try {
      console.log(`[BLE] Waiting for device ${MAC_ADDRESS}…`);
      // Start discovery if not already:
      if (! await this.adapter.isDiscovering()) {
        await this.adapter.startDiscovery();
      }

      // Wait for the device to appear in discovery:
      this.device = await this.adapter.waitDevice(MAC_ADDRESS, 30000);
      console.log(`[BLE] Device found: ${MAC_ADDRESS}`);

      // Stop discovery (optional, reduces BLE noise):
      try { await this.adapter.stopDiscovery(); } catch { /* ignore */ }

      // Connect:
      await this.device.connect();
      console.log(`[BLE] Connected to ${MAC_ADDRESS}`);
      this.isConnected = true;
      this.setupDisconnectListener();

      // Obtain GATT server, service, and characteristics:
      this.gattServer = await this.device.gatt();
      const service: GattService = await this.gattServer.getPrimaryService(LOCK_SERVICE_UUID);
      this.writeChar = await service.getCharacteristic(WRITE_CHAR_UUID);
      this.notifyChar = await service.getCharacteristic(NOTIFY_CHAR_UUID);

      // Set up notifications on the notifyChar:
      await this.notifyChar.startNotifications();
      this.notifyChar.on('valuechanged', (data: Buffer) => this.handleNotification(data));

      // Immediately query status (battery + lock state):
      this.sendGetStatus();

    } catch (err) {
      console.error('[BLE] Connection error:', err);
      this.scheduleReconnect();
    }
  }

  // On unexpected disconnect, schedule a reconnect:
  private setupDisconnectListener(): void {
    this.device.on('disconnect', () => {
      console.warn(`[BLE] Device ${MAC_ADDRESS} disconnected!`);
      this.isConnected = false;
      this.scheduleReconnect();
    });
  }

  private scheduleReconnect(delayMs = 5000): void {
    if (this.reconnectTimeout) {
      return;
    }
    console.log(`[BLE] Scheduling reconnect in ${delayMs/1000}s…`);
    this.reconnectTimeout = setTimeout(() => {
      this.reconnectTimeout = undefined;
      this.attemptConnectLoop();
    }, delayMs);
  }

  // Build & send a “GET_STATUS” frame:
  public async sendGetStatus(): Promise<void> {
    if (!this.isConnected) return;
    const pkt = buildCommandPacket(CommandID.GET_STATUS, Buffer.alloc(0));
    const enc = aesEncrypt(pkt);
    try {
      await this.writeChar.writeValueWithoutResponse(enc);
      console.log('[BLE→] GET_STATUS sent');
    } catch (err) {
      console.error('[BLE] Error writing GET_STATUS:', err);
    }
  }

  // Build & send a “LOCK” frame:
  public async sendLockCommand(): Promise<void> {
    if (!this.isConnected) throw new Error('Not connected to lock');
    const pkt = buildCommandPacket(CommandID.LOCK_DOOR, Buffer.alloc(0));
    const enc = aesEncrypt(pkt);
    try {
      await this.writeChar.writeValueWithoutResponse(enc);
      console.log('[BLE→] LOCK sent');
    } catch (err) {
      console.error('[BLE] Error writing LOCK:', err);
    }
  }

  // Build & send an “UNLOCK” frame:
  public async sendUnlockCommand(): Promise<void> {
    if (!this.isConnected) throw new Error('Not connected to lock');
    const pkt = buildCommandPacket(CommandID.UNLOCK_DOOR, Buffer.alloc(0));
    const enc = aesEncrypt(pkt);
    try {
      await this.writeChar.writeValueWithoutResponse(enc);
      console.log('[BLE→] UNLOCK sent');
    } catch (err) {
      console.error('[BLE] Error writing UNLOCK:', err);
    }
  }

  // Handle incoming notifications (encrypted 16-byte blobs):
  private handleNotification(data: Buffer): void {
    try {
      const decrypted = aesDecrypt(data);
      const frame = parseResponseFrame(decrypted);
      // frame.cmdId will be the command context (e.g. GET_STATUS response)
      // frame.payload includes raw status bytes. Typically payload length = 3:
      //   [lockState (1)] [batteryLevel (1)] [batteryStatus (1)]
      // e.g. lockState: 0x00 = unlocked, 0x01 = locked, 0x02 = moving, etc.
      // batteryLevel: 0x00..0x64 = percentage,
      // batteryStatus: 0x00 = OK, 0x01 = low.
      console.log('[BLE←] Notification decrypted:', frame);

      // Only propagate if it’s a GET_STATUS response:
      if (frame.cmdId === CommandID.GET_STATUS) {
        const lockStateRaw = frame.payload.readUInt8(0);
        const batteryLevel = frame.payload.readUInt8(1);
        const batteryStatusRaw = frame.payload.readUInt8(2);
        let hkCurrent: number;
        switch (lockStateRaw) {
          case 0x00: // “unlocked”
            hkCurrent = HK_LOCK_CURRENT_STATE.UNSECURED; // 0
            break;
          case 0x01: // “locked”
            hkCurrent = HK_LOCK_CURRENT_STATE.SECURED;   // 1
            break;
          case 0x02: // “moving” (transition)
            hkCurrent = HK_LOCK_CURRENT_STATE.UNKNOWN;   // 3
            break;
          case 0x03: // “jammed”
            hkCurrent = HK_LOCK_CURRENT_STATE.JAMMED;    // 2
            break;
          default:
            hkCurrent = HK_LOCK_CURRENT_STATE.UNKNOWN;   // 3
            break;
        }
        const isLowBattery = batteryStatusRaw === 0x01;

        // Emit a “status” event so HomeKit can update:
        this.emit('status', { hkCurrent, batteryLevel, isLowBattery });
      }

    } catch (err) {
      console.error('[BLE] Error handling notification:', err);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HOMEKIT SETUP
// ─────────────────────────────────────────────────────────────────────────────

// 1) Create a HomeKit Accessory
const accessoryUUID = hapUUID.generate(ACCESSORY_NAME + ACCESSORY_SERIAL);
const lockAccessory = new Accessory(ACCESSORY_NAME, accessoryUUID);

// 2) Set basic accessory information
lockAccessory
  .getService(Service.AccessoryInformation)!
  .setCharacteristic(Characteristic.Manufacturer, ACCESSORY_MANUFACTURER)
  .setCharacteristic(Characteristic.Model, ACCESSORY_MODEL)
  .setCharacteristic(Characteristic.SerialNumber, ACCESSORY_SERIAL);

// 3) Add LockMechanism service
const lockService = lockAccessory.addService(Service.LockMechanism, ACCESSORY_NAME);
lockService
  .getCharacteristic(Characteristic.LockCurrentState)
  .on(CharacteristicEventTypes.GET, (callback) => {
    // We’ll update this whenever we get a BLE notification. For now, respond unknown.
    callback(null, HK_LOCK_CURRENT_STATE.UNKNOWN);
  });

lockService
  .getCharacteristic(Characteristic.LockTargetState)
  .on(CharacteristicEventTypes.GET, (callback) => {
    // We could track the “desired state” in local state if needed.
    callback(null, HK_LOCK_TARGET_STATE.SECURED);
  })
  .on(CharacteristicEventTypes.SET, async (value, callback) => {
    // value: 0 = UNSECURED (unlock), 1 = SECURED (lock)
    try {
      if (value === HK_LOCK_TARGET_STATE.UNSECURED) {
        console.log('[HomeKit] Set target to UNLOCK');
        await eqiva.sendUnlockCommand();
      } else {
        console.log('[HomeKit] Set target to LOCK');
        await eqiva.sendLockCommand();
      }
      callback(null);
    } catch (err) {
      console.error('[HomeKit] Error sending lock/unlock:', err);
      callback(err as any);
    }
  });

// 4) Add Battery service
const batteryService = lockAccessory.addService(Service.Battery);
batteryService
  .getCharacteristic(Characteristic.StatusLowBattery)
  .on(CharacteristicEventTypes.GET, (callback) => {
    // We’ll update this as soon as we have a status from BLE.
    callback(null, 0); // 0 = Battery Normal, 1 = Battery Low
  });
batteryService
  .getCharacteristic(Characteristic.BatteryLevel)
  .on(CharacteristicEventTypes.GET, (callback) => {
    callback(null, 100); // Default to 100% until first status update
  });

// 5) “Publish” the accessory on the local network (mDNS)
lockAccessory.publish({
  username: HOMEKIT_ACCESSORY_USERNAME,
  pincode: HOMEKIT_ACCESSORY_PIN,
  category: Categories.DOOR_LOCK,
});
console.log(`[HomeKit] "${ACCESSORY_NAME}" published as a Lock accessory.`);

// ─────────────────────────────────────────────────────────────────────────────
// “Glue” everything together
// ─────────────────────────────────────────────────────────────────────────────

const eqiva = new EqivaLock();

// When EqivaLock emits a “status” event, update HomeKit characteristics:
eqiva.on('status', ({ hkCurrent, batteryLevel, isLowBattery }) => {
  console.log(`[HomeKit] LockCurrentState=${hkCurrent}, Battery=${batteryLevel}% (Low=${isLowBattery})`);

  // LockCurrentState = 1 (SECURED) if locked, else 3 (UNSECURED)
  lockService.setCharacteristic(
    Characteristic.LockCurrentState,
    hkCurrent
  );

  // Battery level (0…100)
  batteryService.setCharacteristic(Characteristic.BatteryLevel, batteryLevel);
  // StatusLowBattery (0 = Normal, 1 = Low)
  batteryService.setCharacteristic(
    Characteristic.StatusLowBattery,
    isLowBattery ? 1 : 0
  );
});

// Start BLE / Eqiva connection:
eqiva.start()
  .then(() => console.log('[BLE] EqivaLock.start() completed'))
  .catch(err => console.error('[BLE] EqivaLock.start() error:', err));

// Clean up on process exit:
process.on('SIGINT', () => {
  console.log('[Process] SIGINT received, cleaning up…');
  lockAccessory.unpublish();
  eqiva.destroy();   // terminate node-ble session
  process.exit(0);
});
