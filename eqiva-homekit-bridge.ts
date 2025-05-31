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
const HOMEKIT_ACCESSORY_NAME     = 'Eqiva Smart Lock';
const HOMEKIT_ACCESSORY_MANUFACTURER = 'Eqiva';
const HOMEKIT_ACCESSORY_MODEL    = 'eQ-3 Bluetooth Smart Lock';
const HOMEKIT_ACCESSORY_SERIAL   = '1234567890';

// ─────────────────────────────────────────────────────────────────────────────




/***** ───────────────────────── CONSTANTS ───────────────────────── ******/

// BLE GATT
const LOCK_SERVICE_UUID  = '58e06900-15d8-11e6-b737-0002a5d5c51b';
const WRITE_CHAR_UUID    = '3141dd40-15db-11e6-a24b-0002a5d5c51b';
const NOTIFY_CHAR_UUID   = '359d4820-15db-11e6-82bd-0002a5d5c51b';

// keyble message type IDs (subset)
const MT = {
  CONNECTION_REQUEST: 0x02,
  CONNECTION_INFO:    0x03,
  STATUS_REQUEST:     0x82,
  STATUS_INFO:        0x83,
  COMMAND:            0x87,
  FRAGMENT_ACK:       0x00,
  CLOSE_CONNECTION:   0x06,
} as const;

// command IDs
enum CommandID { LOCK=0, UNLOCK=1, OPEN=2, }

// HomeKit states
const HK_LOCK_CURRENT_STATE = { UNSECURED:0, SECURED:1, JAMMED:2, UNKNOWN:3 } as const;
const HK_LOCK_TARGET_STATE  = { UNSECURED:0, SECURED:1 } as const;

// Node imports
import { createBluetooth, Bluetooth, Adapter, Device, GattServer, GattCharacteristic, GattService } from 'node-ble';
import { Accessory, Service, Characteristic, CharacteristicEventTypes, uuid as hapUUID, Categories } from 'hap-nodejs';
import { randomBytes, createCipheriv } from 'crypto';
import { EventEmitter } from 'events';

/***** ─────────────────── LOW‑LEVEL PROTOCOL HELPERS ─────────────────── *****/

const AES_KEY = Buffer.from(USER_KEY_HEX, 'hex');

function aesEcbEncrypt(block16: Buffer): Buffer {
  const cipher = createCipheriv('aes-128-ecb', AES_KEY, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block16), cipher.final()]);
}

function xor(a: Buffer, b: Buffer): Buffer {
  const out = Buffer.alloc(a.length);
  for (let i=0;i<a.length;i++) out[i] = a[i] ^ b[i];
  return out;
}

// Generic ceil helper (same as keyble generic_ceil())
const genericCeil = (x: number, step=16) => (Math.ceil(x/step)*step);

// Convert int to BE Uint8Array
const i2ba = (n: number, bytes: number): Buffer => {
  const b = Buffer.alloc(bytes);
  for (let i=0;i<bytes;i++) b[bytes-1-i] = (n >> (i*8)) & 0xff;
  return b;
};

/** Compute nonce used by keyble’s CTR‑like stream */
function computeNonce(messageType: number, sessionNonce: Buffer, securityCounter: number): Buffer {
  return Buffer.concat([
    Buffer.from([messageType]),
    sessionNonce,                         // 8 bytes
    Buffer.from([0x00,0x00]),             // unknown / always 0
    i2ba(securityCounter, 2)              // 2 bytes, BE
  ]);                                     // total 13 bytes
}

/** keyble “cryptData” – XOR plain with keystream derived from AES‑ECB */
function cryptData(data: Buffer, mt: number, sessionNonce: Buffer, secCounter: number): Buffer {
  const nonce = computeNonce(mt, sessionNonce, secCounter);
  const blocks = Math.ceil(data.length/16);
  const keystream: Buffer[] = [];
  for (let i=0;i<blocks;i++) {
    const ctrBlock = Buffer.concat([
      Buffer.from([1]),     // constant 1
      nonce,                // 13 bytes
      i2ba(i+1,2),          // counter (1‑based)
    ]); // 16 bytes
    keystream.push(aesEcbEncrypt(ctrBlock));
  }
  const ks = Buffer.concat(keystream).slice(0, data.length);
  return xor(data, ks);
}

/** keyble “computeAuthenticationValue” – 4‑byte MIC */
function computeAuth(data: Buffer, mt: number, sessionNonce: Buffer, secCounter: number): Buffer {
  const nonce = computeNonce(mt, sessionNonce, secCounter);
  const paddedLen = genericCeil(data.length,16);
  const padded = Buffer.concat([data, Buffer.alloc(paddedLen-data.length)]);
  let x = aesEcbEncrypt(Buffer.concat([Buffer.from([9]), nonce, i2ba(data.length,2)]));
  for (let off=0; off<paddedLen; off+=16) {
    x = aesEcbEncrypt(xor(x, padded.slice(off, off+16)));
  }
  const s0 = aesEcbEncrypt(Buffer.concat([Buffer.from([1]), nonce, Buffer.from([0x00,0x00])]))
  return xor(x.slice(0,4), s0);
}

/***** ───────────────────── MESSAGE (DE)FRAGMENTATION ─────────────────── *****/

function splitIntoFragments(full: Buffer): Buffer[] {
  const chunks: Buffer[] = [];
  for (let i=0;i<full.length; i+=15) chunks.push(full.slice(i,i+15));
  return chunks.map((chunk,idx)=>{
    const remaining = chunks.length-1-idx;
    const status = remaining | (idx===0?0x80:0x00);
    return Buffer.concat([Buffer.from([status]), chunk, Buffer.alloc(15-chunk.length)]);
  });
}

function buildUnsecured(mt: number, data: Buffer): Buffer[] {
  return splitIntoFragments(Buffer.concat([Buffer.from([mt]), data]));
}

function buildSecured(mt: number, dataPlain: Buffer, sessNonce: Buffer, secCounter: number): Buffer[] {
  // pad dataPlain to multiple of 16 before encryption as per keyble
  const paddedLen = genericCeil(dataPlain.length,16);
  const padded = Buffer.concat([dataPlain, Buffer.alloc(paddedLen-dataPlain.length)]);
  const crypted = cryptData(padded, mt, sessNonce, secCounter);
  const auth = computeAuth(padded, mt, sessNonce, secCounter);
  const final = Buffer.concat([Buffer.from([mt]), crypted, i2ba(secCounter,2), auth]);
  return splitIntoFragments(final);
}

/***** ────────────────────── BLE / PROTOCOL CLASS ─────────────────────── *****/

class EqivaLock extends EventEmitter {
  private bluetooth: Bluetooth; private adapter!: Adapter; private device!: Device;
  private gatt!: GattServer; private write!: GattCharacteristic; private notify!: GattCharacteristic;
  private connected = false; private reconnectTimer?: NodeJS.Timeout;

  private localSessNonce = Buffer.alloc(8);      // generated on connect
  private remoteSessNonce = Buffer.alloc(8);
  private localSecCounter = 1;                   // increments with each secure tx
  private remoteSecCounter = 0;

  constructor() { super(); this.bluetooth = createBluetooth().bluetooth; }

  async start() { this.adapter = await this.bluetooth.defaultAdapter(); await this.loopConnect(); }

  private async loopConnect() {
    try {
      console.log(`[BLE] Waiting for ${MAC_ADDRESS}…`);
      if(!await this.adapter.isDiscovering()) await this.adapter.startDiscovery();
      this.device = await this.adapter.waitDevice(MAC_ADDRESS,30000);
      await this.adapter.stopDiscovery();
      await this.device.connect();
      this.connected = true;
      console.log(`[BLE] Connected.`);
      this.device.on('disconnect',()=>{console.warn('[BLE] disconnect');this.connected=false;this.scheduleReconnect();});

      this.gatt = await this.device.gatt();
      const svc: GattService = await this.gatt.getPrimaryService(LOCK_SERVICE_UUID);
      this.write = await svc.getCharacteristic(WRITE_CHAR_UUID);
      this.notify = await svc.getCharacteristic(NOTIFY_CHAR_UUID);
      await this.notify.startNotifications();
      this.notify.on('valuechanged', d=>this.onNotify(d));

      await this.performHandshake();
      await this.requestStatus();
    } catch(e){ console.error('[BLE] error',e); this.scheduleReconnect(); }
  }

  private scheduleReconnect(ms=5000){ if(this.reconnectTimer) return; this.reconnectTimer=setTimeout(()=>{this.reconnectTimer=undefined; this.loopConnect();},ms); }

  private async performHandshake(){
    this.localSessNonce = randomBytes(8);
    // 1) send CONNECTION_REQUEST (unsecured)
    const reqData = Buffer.concat([Buffer.from([USER_ID]), this.localSessNonce]);
    await this.sendFragments(buildUnsecured(MT.CONNECTION_REQUEST, reqData));
    console.log('[BLE→] CONNECTION_REQUEST');
    // 2) wait for CONNECTION_INFO
    await this.waitEvent('handshake-done',5000);
  }

  private async requestStatus(){
    const now = new Date();
    const data = Buffer.from([
      now.getFullYear()-2000,
      now.getMonth()+1,
      now.getDate(), now.getHours(), now.getMinutes(), now.getSeconds()
    ]);
    await this.sendFragments(buildSecured(MT.STATUS_REQUEST, data, this.remoteSessNonce, this.localSecCounter++));
    console.log('[BLE→] STATUS_REQUEST');
  }

  public async sendLock(){ await this.sendCmd(CommandID.LOCK); }
  public async sendUnlock(){ await this.sendCmd(CommandID.UNLOCK); }

  private async sendCmd(cmd: CommandID){
    const data = Buffer.from([cmd]);
    await this.sendFragments(buildSecured(MT.COMMAND, data, this.remoteSessNonce, this.localSecCounter++));
    console.log(`[BLE→] ${(cmd===0?'LOCK':'UNLOCK')} sent`);
  }

  private async sendFragments(frags: Buffer[]){ for(const f of frags) await this.write.writeValueWithoutResponse(f); }

  /***** ────────────── INCOMING NOTIFICATIONS ───────────── */
  private rxBuffer: Buffer[] = [];
  private onNotify(pkt16: Buffer){
    const status = pkt16.readUInt8(0);
    const isFirst = !!(status & 0x80);
    const remaining = status & 0x7f;
    const chunk = pkt16.slice(1);
    if(isFirst) this.rxBuffer = [];
    this.rxBuffer.push(chunk);
    if(remaining===0){
      const full = Buffer.concat(this.rxBuffer).slice(0,15*this.rxBuffer.length - (15- chunk.length));
      const mt = full.readUInt8(0);
      const body = full.slice(1);
      this.handleMessage(mt, body);
    }
  }

  private handleMessage(mt:number, body:Buffer){
    switch(mt){
      case MT.CONNECTION_INFO:{
        this.remoteSessNonce = body.slice(1,9); // skip user_id
        console.log('[BLE←] CONNECTION_INFO');
        this.emit('handshake-done');
        break;}
      case MT.STATUS_INFO:{
        // body = encrypted+secCtr+auth (variable)
        const secCtr = body.readUInt16BE(body.length-6);
        if(secCtr<=this.remoteSecCounter) return; // stale
        this.remoteSecCounter = secCtr;
        const auth = body.slice(-4);
        const enc = body.slice(0,-6);
        const plain = cryptData(enc, MT.STATUS_INFO, this.localSessNonce, secCtr);
        const mic = computeAuth(plain, MT.STATUS_INFO, this.localSessNonce, secCtr);
        if(!mic.equals(auth)){ console.warn('AUTH FAIL'); return; }
        const lockStatus = plain.readUInt8(2) & 0x07; // see keyble docs
        const batteryLow = (plain.readUInt8(1)&0x80)!==0;
        let hk:number=HK_LOCK_CURRENT_STATE.UNKNOWN;
        if(lockStatus===2) hk=HK_LOCK_CURRENT_STATE.UNSECURED;
        else if(lockStatus===3) hk=HK_LOCK_CURRENT_STATE.SECURED;
        else if(lockStatus===4) hk=HK_LOCK_CURRENT_STATE.UNSECURED;
        else if(lockStatus===0) hk=HK_LOCK_CURRENT_STATE.UNKNOWN;
        this.emit('status', { hkCurrent: hk, isLowBattery: batteryLow });
        break;}
      default:
        console.log(`[BLE←] Unknown MT ${mt.toString(16)}`);
    }
  }

  private async waitEvent(ev:string,timeout:number){ return new Promise((res,rej)=>{const t=setTimeout(()=>rej(new Error('timeout')),timeout); this.once(ev,(...a)=>{clearTimeout(t);res(a);});}); }
}

/***** ────────────────────── HOMEKIT SETUP ─────────────────────────*****/

const accessoryUUID = hapUUID.generate(HOMEKIT_ACCESSORY_NAME+HOMEKIT_ACCESSORY_SERIAL);
const accessory = new Accessory(HOMEKIT_ACCESSORY_NAME, accessoryUUID);
accessory.getService(Service.AccessoryInformation)!
  .setCharacteristic(Characteristic.Manufacturer, HOMEKIT_ACCESSORY_MANUFACTURER)
  .setCharacteristic(Characteristic.Model, HOMEKIT_ACCESSORY_MODEL)
  .setCharacteristic(Characteristic.SerialNumber, HOMEKIT_ACCESSORY_SERIAL);

const lockService = accessory.addService(Service.LockMechanism, HOMEKIT_ACCESSORY_NAME);
const batteryService = accessory.addService(Service.Battery);

lockService.getCharacteristic(Characteristic.LockTargetState)
  .on(CharacteristicEventTypes.SET, async (value,cb)=>{
    try{
      if(value===HK_LOCK_TARGET_STATE.UNSECURED) await eqiva.sendUnlock();
      else await eqiva.sendLock();
      cb(null);
    }catch(e){ cb(e as any); }
  });

accessory.publish({ username: HOMEKIT_ACCESSORY_USERNAME, pincode: HOMEKIT_ACCESSORY_PIN, category: Categories.DOOR_LOCK });
console.log('[HomeKit] accessory published.');

/***** ───────────────────────── MAIN ───────────────────────── *****/

const eqiva = new EqivaLock();
eqiva.on('status', ({hkCurrent,isLowBattery})=>{
  lockService.updateCharacteristic(Characteristic.LockCurrentState, hkCurrent);
  batteryService.updateCharacteristic(Characteristic.StatusLowBattery, isLowBattery?1:0);
});

eqiva.start().catch(console.error);

process.on('SIGINT', ()=>{ console.log('Exiting…'); accessory.unpublish(); process.exit(0); });
