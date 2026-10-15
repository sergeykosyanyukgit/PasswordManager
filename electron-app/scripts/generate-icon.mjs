import { writeFile } from 'node:fs/promises';
import pngToIco from 'png-to-ico';

// The user-supplied notebook artwork is shared by the UI and Windows executable.
await writeFile('build/icon.ico', await pngToIco('src/renderer/assets/mynotes.png'));
