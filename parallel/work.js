const fs = require('fs').promises;
const path = require('path');
const os = require('os');

const { spawn } = require('child_process');
const { EventEmitter } = require('events');


async function* walk(dir) {
  const ignored = new Set('.id0,.id1,.nam,.log,.til,.idb,.js,.py,.DS_Store'.split(','));
  const files = await fs.readdir(dir);

  for (file of files) {
    const ext = path.extname(file).toLowerCase();
    if (ignored.has(ext)) {
      continue;
    }
    const joint = path.join(dir, file);
    try {
      const stat = await fs.stat(joint);
      if (stat.isDirectory()) {
        yield* walk(joint);
      } else {
        yield joint;
      }
    } catch(_) {
      continue;
    }
  }
}

class Parallel extends EventEmitter {
  constructor(py, base, count) {
    super();
    this.py = py;
    this.max = count || 4; //os.cpus().length;
    this.pool = new Set();
    this.workspace = base

    process.on('SIGINT', () => {
      this.removeAllListeners();
      this.pool.forEach(p => p.kill());
      process.exit();
    });
  }

  spawn(cmd, filename) {
    const name = path.basename(filename);
    const log = path.join(this.workspace, `${name}.log`);
    console.log([cmd, '-A', `-S"${this.py}"`, `-L${log}`, filename].join(' '))
    const child = spawn(cmd, ['-A', `-S${this.py}`, `-L${log}`, filename]);
    this.pool.add(child);
    child.on('close', (code) => {
      this.pool.delete(child);
      this.emit('finish', { name, code });
    });
    child.on('error', () => {

    });
    return child;
  }

  async consume(name) {
    const cmd = 'ida64'
    if (this.pool.size >= this.max) {
      await new Promise(resolve => this.once('finish', resolve)).catch(e => console.error(e));
    }
    try {
      this.spawn(cmd, name);
    } catch(e) {
      console.log(e);
    }
  }
}

async function main(cwd, script, base) {
  const py = path.join(__dirname, '..', 'src', script);
  const job = new Parallel(py, base);
  for await (let name of walk(cwd)) {
    await job.consume(name);
  }
}

/**
 * ln -s ~/.idapro/ida.reg .idapro/ida.reg
 */

// disable plugins
// process.env.IDAUSR = path.join(__dirname, '..', '.idapro');

main(process.argv[2], process.argv[3], process.argv[4]);
