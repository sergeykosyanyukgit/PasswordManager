// Used by both the packaged response header and the renderer's HTML meta tag.
// xterm's DOM renderer generates <style> elements for cell layout, cursor and
// selection, plus style attributes for truecolor/contrast. Inline CSS is
// required; inline scripts and remote styles remain blocked. SSH output is
// terminal text and must never be inserted as HTML.
export const CONTENT_SECURITY_POLICY = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'";
