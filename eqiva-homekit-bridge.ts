// eqiva-homekit-bridge.ts
// -----------------------------------------------------------------------------
// A single‑file TypeScript re‑implementation of the essential parts of the
// open‑source "keyble" library, wired up to HAP‑nodejs so the eQ‑3/eqiva
// Bluetooth Smart Lock appears as a native HomeKit accessory.
// The file is meant to be executed with ts-node *or* compiled with tsc and
// started with Node >= 18 on an Ubuntu / Raspberry Pi host.
// -----------------------------------------------------------------------------
// HARD‑CODE THE CREDENTIALS FOR **YOUR** LOCK HERE BEFORE BUILDING/RUNNING
// -----------------------------------------------------------------------------
const MAC_ADDRESS = "01:23:45:67:89:0a";
const USER_ID     = 123;
const USER_KEY    = "1234567890abcdef1234567890abcdef";

const HOMEKIT_ACCESSORY_MAC = "ab:12:cd:34:ef:56" // set to random value
const HOMEKIT_ACCESSORY_PIN = "123-45-678" // set to random value
// -----------------------------------------------------------------------------

/*
 * External dependencies — install with
 *   npm i node-ble aes-js hap-nodejs uuid tslib @types/node
 * (HAP‑nodejs already bundles the HomeKit definitions.)
 */
import { createBluetooth, Adapter, Device, GattCharacteristic } from "node-ble";
import * as aesjs from "aes-js";
import { Accessory, Categories, Characteristic, CharacteristicEventTypes, Service, uuid } from "hap-nodejs";
import { EventEmitter } from "events";

// -----------------------------------------------------------------------------
// Section 1 – Low‑level protocol helpers (excerpted and translated from keyble)
// -----------------------------------------------------------------------------

/*
 * Bluetooth LE UUIDs that the eqiva lock exposes. They are the same constants
 * used by the original keyble implementation but written without hyphens so
 * node‑ble’s DBus backend accepts them without complaining.
 */
const SERVICE_UUID              = "58e0690015d811e6b7370002a5d5c51b";
const SEND_CHARACTERISTIC_UUID   = "3141dd4015db11e6a24b0002a5d5c51b";
const RECEIVE_CHARACTERISTIC_UUID= "359d482015db11e682bd0002a5d5c51b";

// Keyble interprets every packet as an 8‑byte header + up to 13 bytes payload.
// The header layout (big‑endian) is documented in the original repo; we keep
// the structure for compatibility so that the lock firmware accepts us.

/* MESSAGE TYPE IDS (only the ones we actually *send* in this bridge) */
const CONNECTION_REQUEST   = 0x02;
const COMMAND              = 0x87;
const STATUS_REQUEST       = 0x82;
/* COMMAND IDs understood by the firmware */
const CMD_LOCK   = 0x00;
const CMD_UNLOCK = 0x01;
const CMD_OPEN   = 0x02;

/* LOCK STATUS IDs reported by STATUS_INFO messages (0x83)                 */
/* See keyble → src/message_types.js; we only care about the three below */
const STATUS_MOVING  = 1;
const STATUS_UNLOCKED= 2;
const STATUS_LOCKED  = 3;
const STATUS_OPENED  = 4;

/* -------------------------------------------------------------------------- */
/* Little helper util functions (ported from keyble/utils.js)                 */
/* -------------------------------------------------------------------------- */
const hexToUint8 = (hex: string): Uint8Array => {
  if (hex.length % 2) throw new Error("hex string must have even length");
  return new Uint8Array(hex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
};
const uint16 = (n: number): Uint8Array => new Uint8Array([(n>>8)&0xff, n&0xff]);
const pad16 = (data: Uint8Array): Uint8Array => {
  const len = ((data.length + 15) & ~15); // round up to multiple of 16
  const out = new Uint8Array(len);
  out.set(data);
  return out;
};
/* AES‑ECB 128‑bit primitive (uses aes‑js) */
const aesEcbEncrypt = (data: Uint8Array, key: Uint8Array): Uint8Array =>
  (new aesjs.ModeOfOperation.ecb(key)).encrypt(data);
const aesEcbDecrypt = (data: Uint8Array, key: Uint8Array): Uint8Array =>
  (new aesjs.ModeOfOperation.ecb(key)).decrypt(data);

/* -------------------------------------------------------------------------- */
/* Security helpers – identical to keyble’s reference implementation          */
/* -------------------------------------------------------------------------- */
const cryptData = (
  data: Uint8Array,
  msgId: number,
  remoteNonce: Uint8Array,
  counter: number,
  key: Uint8Array,
): Uint8Array => {
  const iv = new Uint8Array([msgId, ...remoteNonce, ...uint16(counter)]);
  const ecbKey = aesEcbEncrypt(iv, key);
  const out = new Uint8Array(data.length);
  for (let i=0;i<data.length;i++) out[i] = data[i] ^ ecbKey[i % 16];
  return out;
};
const authValue = (
  data: Uint8Array,
  msgId: number,
  remoteNonce: Uint8Array,
  counter: number,
  key: Uint8Array,
): Uint8Array => {
  const msg = new Uint8Array([msgId, ...remoteNonce, ...uint16(counter), ...data]);
  const digest = aesEcbEncrypt(pad16(msg), key);
  return digest.slice(0,2); // first two bytes
};

// -----------------------------------------------------------------------------
// Section 2 – EqivaLock class (maintains BLE session + high‑level API)
// -----------------------------------------------------------------------------

class EqivaLock extends EventEmitter {
  private adapter!: Adapter;
  private device!: Device;
  private tx!: GattCharacteristic; // send characteristic
  private rx!: GattCharacteristic; // receive characteristic

  private readonly userId = USER_ID;
  private readonly userKey = hexToUint8(USER_KEY);
  private readonly mac     = MAC_ADDRESS.toLowerCase();

  private localCounter = 1;
  private remoteNonce!: Uint8Array;

  private connected = false;
  private connectPromise: Promise<void> | null = null;

  constructor(private readonly autoReconnect = true) {
    super();
    void this.connect(); // async bootstrap
  }

  //-----------------------------------------------------------
  // Public **high‑level** ops used by the HomeKit bridge
  //-----------------------------------------------------------

  public async lock ()   { await this.sendCommand(CMD_LOCK  ); }
  public async unlock()  { await this.sendCommand(CMD_UNLOCK); }
  public async open ()   { await this.sendCommand(CMD_OPEN  ); }
  public async status()  { await this.sendStatusRequest();   }

  //-----------------------------------------------------------
  // BLE connection lifecycle
  //-----------------------------------------------------------

  private async connect(): Promise<void> {
    if (this.connectPromise) return this.connectPromise; // serialise
    this.connectPromise = (async () => {
      const { bluetooth } = createBluetooth();
      this.adapter = await bluetooth.defaultAdapter();
      await this.adapter.stopDiscovery().catch(()=>{}); // nicer when re‑connecting
      this.device  = await this.adapter.waitDevice(this.mac);
      this.device.on("disconnect", () => {
        this.connected = false;
        this.emit("disconnected");
        if (this.autoReconnect) {
          setTimeout(()=>void this.connect().catch(()=>{}), 2000);
        }
      });
      await this.device.connect();
      const gatt = await this.device.gatt();
      const service = await gatt.getPrimaryService(SERVICE_UUID);
      this.tx = await service.getCharacteristic(SEND_CHARACTERISTIC_UUID);
      this.rx = await service.getCharacteristic(RECEIVE_CHARACTERISTIC_UUID);
      this.rx.on("valuechanged", (buf: Buffer) => this.onNotification(new Uint8Array(buf)));
      await this.rx.startNotifications();
      this.connected = true;
      await this.performHandshake();
      this.emit("ready");
    })();
    try { await this.connectPromise; } finally { this.connectPromise = null; }
  }

  //-----------------------------------------------------------
  // Security handshake (very abridged version of keyble’s FSM)
  //-----------------------------------------------------------

  private async performHandshake() {
    // Generate 8‑byte local nonce
    const localNonce = aesjs.utils.hex.toBytes(uuid.generate("v4").replace(/-/g, "").slice(0,16));
    await this.sendPlain(CONNECTION_REQUEST, new Uint8Array([this.userId, ...localNonce]));
    // Wait until we have parsed STATUS_INFO once (sets remoteNonce)
    await new Promise<void>(resolve => this.once("handshake_done", () => resolve()));
  }

  //-----------------------------------------------------------
  // Message encoding / decoding
  //-----------------------------------------------------------

  private async sendPlain(id: number, payload: Uint8Array) {
    const frame = new Uint8Array([id, payload.length, ...payload]);
    await this.tx.writeValue(Buffer.from(frame));
  }

  private async sendSecure(id: number, payload: Uint8Array) {
    const padded = pad16(payload);
    const enc    = cryptData(padded, id, this.remoteNonce, this.localCounter, this.userKey);
    const auth   = authValue(padded, id, this.remoteNonce, this.localCounter, this.userKey);
    const frame  = new Uint8Array([id, enc.length+2+2, ...enc, ...uint16(this.localCounter), ...auth]);
    this.localCounter = (this.localCounter + 1) & 0xffff;
    await this.tx.writeValue(Buffer.from(frame));
  }

  private async sendCommand(cmdId: number) {
    await this.ensureConnected();
    await this.sendSecure(COMMAND, new Uint8Array([cmdId]));
  }

  private async sendStatusRequest() {
    await this.ensureConnected();
    const now = new Date();
    const payload = new Uint8Array([
      now.getFullYear()-2000,
      now.getMonth()+1,
      now.getDate(),
      now.getHours(),
      now.getMinutes(),
      now.getSeconds(),
      now.getDay(),
    ]);
    await this.sendSecure(STATUS_REQUEST, payload);
  }

  private async ensureConnected() { if (!this.connected) await this.connect(); }

  //-----------------------------------------------------------
  // Incoming notification parsing (super simplified)
  //-----------------------------------------------------------

  private onNotification(frame: Uint8Array) {
    const id   = frame[0];
    const len  = frame[1];
    const data = frame.slice(2, 2+len);
    switch (id) {
      case 0x03: { // CONNECTION_INFO → contains remote nonce
        this.remoteNonce = data.slice(1,9);
        break;
      }
      case 0x83: { // STATUS_INFO
        const batteryLow = (data[1] & 0x80) !== 0;
        const statusId   = data[2] & 0x07;
        this.emit("status", { batteryLow, statusId });
        this.emit("handshake_done");
        break;
      }
      default:
        // Other message types are ignored here
        break;
    }
  }
}

// -----------------------------------------------------------------------------
// Section 3 – HomeKit bridge using HAP‑nodejs
// -----------------------------------------------------------------------------

const lock = new EqivaLock();

const accessoryUUID = uuid.generate("eqiva-lock-" + MAC_ADDRESS);
const eqivaAccessory = new Accessory("Eqiva Lock", accessoryUUID);

// Mandatory service: LockMechanism
const lockService = eqivaAccessory.addService(Service.LockMechanism, "Door Lock");
lockService.getCharacteristic(Characteristic.LockCurrentState).on("get", cb => {
  lock.status().catch(()=>{});
  cb(null, Characteristic.LockCurrentState.UNKNOWN);
});
lockService.getCharacteristic(Characteristic.LockTargetState)
  .on("set", (value, cb) => {
    (async()=>{
      if (value === Characteristic.LockTargetState.SECURED) {
        await lock.lock();
      } else if (value === Characteristic.LockTargetState.UNSECURED) {
        await lock.unlock();
      }
      cb(null);
    })().catch(err=>cb(err as Error));
  });

// Optional service: Battery
const battService = eqivaAccessory.addService(Service.Battery);

lock.on("status", ({batteryLow, statusId}) => {
  const current = (statusId === STATUS_LOCKED) ?
    Characteristic.LockCurrentState.SECURED :
    Characteristic.LockCurrentState.UNSECURED;
  lockService.updateCharacteristic(Characteristic.LockCurrentState, current);
  battService.updateCharacteristic(Characteristic.StatusLowBattery,
    batteryLow ? Characteristic.StatusLowBattery.BATTERY_LEVEL_LOW
               : Characteristic.StatusLowBattery.BATTERY_LEVEL_NORMAL);
});

eqivaAccessory.publish({
  username: HOMEKIT_ACCESSORY_MAC,
  pincode:  HOMEKIT_ACCESSORY_PIN,
  category: Categories.DOOR_LOCK,
  port:     0, // random
});

console.log(`Eqiva ➜ HomeKit bridge is up. Add the accessory with the code ${HOMEKIT_ACCESSORY_PIN}.`);

