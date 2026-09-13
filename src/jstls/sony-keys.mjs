import { bytesFromHex } from './bytes.mjs';

// 本文件是生成物：由 webinstaller/gen_sony_keys.py 从 Sony-PMCA-RE 的上游常量重建。
// 与 backend/sony_keys.py 同源；不要手改。
//
//   pmca/spk/constants.py  -> RSA_MODULUS / RSA_EXPONENT / SAMPLE_SPK_KEY / SPK_*
//   pmca/xpd/constants.py  -> XPD_CIC_KEY

export const SPK_MIME_TYPE = 'application/vnd.sony.spk.package-archive';
export const SPK_EXTENSION = '.1.spk';
export const SPK_BLOCK_SIZE = 0x100000;
export const SPK_PADDING_SIZE = 16;

// RSA-2048 模数 + e=65537（相机侧 librsaforinstaller.so 用它）。
// 注意 spk 的「加密」只是 pow(m, e, n)（公钥方向）⇒ 任何人都能造 spk。
export const RSA_MODULUS = BigInt('0x92eb3982c94690fbafe35e3ad5f704be6d846d1c7ffe81724eb09f73e1d377c52bc9281cd0ff2c7c0531191f3e20be38acd3147ff3ff8678111042dac210fcd0c77dc03cfe17471f904de64473d6ad552680c76bd9375c1e7e8eea5a2858a9f18b234e01d10ef182d783187040757d9176d119a2f9360af403c1fcc567bd8cb5b39e49526b4bebe0656cb5ba3110c24400ce2055ab0d4dd5ff25dfabfd115c1ec7388a1138ccc7fae1f67b0e31fd54e147425e15177ec2d525b4cd93d10ad7ba7a1676c5e93f9c02e0ac09fc49cf8c5cd8e8b4a940fc9ae59ee25a0dfed48b7b22e826c6bdb1f53312648d650345e20d9c1abcef55d8731e8dc25593252f81ad');
export const RSA_EXPONENT = 65537n;

// 取自 appstore 的 TouchLessShutter100.1.spk，偏移 0x0C 起 256 字节；
// pow(bytesToBigInt(SAMPLE_SPK_KEY), 65537, RSA_MODULUS) 的最短字节表示 = 16 字节 AES key。
export const SAMPLE_SPK_KEY = bytesFromHex('7e29351425ec82c61ef1d736afadc280966a2dadd53ffee3d55e608afad43951853a1be9e36265b05c1e4345ac4919d6c9ef4e021f58bf85e4851c3cb2bd14416d261526296523259664be8ac2477f7bd6d1c162af286c65a7f57a1800e489cf24fc58fb041f29ea103f5fca3eb996baaf8eea2cfd6431bb765dced8110b341db6d313dc40a82a6e2134272e3aa3c7570b80d5d1d7533f2efcf3ff0a00f91691847417005da841fd2906ac7e0767fafbbb1e7ea0e1c76828ace66fdd449506609cc604c8abf11d9414a7cb296d93841b3a062c05e5a3f340556dc25e6c0e467466242ff433cc200ef9f29d9bbdf6227212ef40bc43cb74b1df02be3153a334a2');

// xpd 的 CIC 校验：HMAC-SHA256(key=XPD_CIC_KEY, msg=url).hexdigest()
// ⚠️ 它是一串 **ASCII 十六进制字符串**（90 字节），不是 45 字节原始数据。
export const XPD_CIC_KEY = bytesFromHex('383539356536386161353064323564636335326234643665366136326166353236656664373532336134636334376532313265383265393739373238643666306464303263376534653739646462333137643536666561326264');
