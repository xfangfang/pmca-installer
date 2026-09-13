/**
 * webpack 打包 + 混淆。
 *
 * 为什么还要打包：
 *   · 把 src/ 下 20 多个模块（页面代码 + src/jstls 里自写的 TLS 服务端/假商店/密码学）
 *     合成**一个文件**，静态托管时请求更少；
 *   · **界面中英词条（src/i18n.js + i18n-en-*.js）也在这个图里** —— 打包版自带语言切换，
 *     dist/index.html 只用 app.min.js 一个文件，不会再单独 import ../src/i18n.js；
 *   · 顺手做**混淆**（标识符十六进制化 + 字符串数组 + 轻度控制流平坦化），
 *     让「页面里怎么当 TLS 服务端」不那么一眼可读。
 * 源码仍是真源：dist/index.html 在没有产物时会自动回退到 ../src/main.js，
 * 所以全新克隆不装 npm 也能直接跑。
 *
 * 产物：dist/app.min.js（ES module；页面用一段动态 import 加载它）
 * 生成物不入库（见 .gitignore）；要发布就 build 一次，然后整个目录传上去。
 *
 * 跑：npm install && npm run build   （Node 12 也能跑：webpack 5.76 + obfuscator 3/4）
 */

const path = require('path');
const WebpackObfuscator = require('webpack-obfuscator');

module.exports = {
  mode: 'production',
  target: ['web', 'es2020'],
  entry: path.resolve(__dirname, 'src', 'main.js'),
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'app.min.js',
    module: true, // 输出 ES module，这样 index.html 里一句 import() 就能加载
    chunkFormat: 'module',
    clean: false, // dist/ 里还有 index.html / style.css / certs，别清
  },
  experiments: {
    outputModule: true,
  },
  resolve: {
    extensions: ['.mjs', '.js'],
  },
  performance: {
    // 单文件几 MB 也不报警：这里面本来就有自写的密码学实现
    hints: false,
    maxEntrypointSize: 8 * 1024 * 1024,
    maxAssetSize: 8 * 1024 * 1024,
  },
  optimization: {
    // 只有一个入口，别拆 vendor，保证产物就是「一个文件」
    splitChunks: false,
    runtimeChunk: false,
    minimize: true,
    minimizer: [new (require('terser-webpack-plugin'))({ terserOptions: { format: { comments: false } } })],
  },
  devtool: false,
  plugins: [
    // 注意：这一步在 terser 之后再跑，所以最终产物是「混淆过」的。
    // 参数刻意保守：控制流平坦化只开一点点、不注入死代码 —— 那两样会让体积翻倍、启动变慢，
    // 而这里的目的只是「不易读」，不是反逆向。
    new WebpackObfuscator(
      {
        compact: true,
        identifierNamesGenerator: 'hexadecimal',
        renameGlobals: false,
        stringArray: true,
        stringArrayThreshold: 0.75,
        stringArrayEncoding: [],
        rotateStringArray: true,
        controlFlowFlattening: true,
        controlFlowFlatteningThreshold: 0.15,
        deadCodeInjection: false,
        selfDefending: false,
        debugProtection: false,
        disableConsoleOutput: false, // 日志面板要靠 console 同步一份，别给关掉
      },
      []
    ),
  ],
};
