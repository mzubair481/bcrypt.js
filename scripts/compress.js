const fs = require('fs');
const { gzip } = require('node-gzip');

async function compressFile() {
    try {
        const content = fs.readFileSync('dist/bcrypt.min.js');
        const compressed = await gzip(content, { level: 9 }); // level 9 is maximum compression
        fs.writeFileSync('dist/bcrypt.min.js.gz', compressed);
        console.log('Successfully compressed bcrypt.min.js');
    } catch (err) {
        console.error('Compression failed:', err);
        process.exit(1);
    }
}

compressFile(); 