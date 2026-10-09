// Strict CSP support: `style-src 'self' 'nonce-…'` without 'unsafe-inline'.
// Monaco creates <style> elements at runtime; we stamp them with the per-response nonce
// injected by the front proxy so the browser accepts them. Must be imported first.
const nonce = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content;

if (nonce && nonce !== "__CSP_NONCE__") {
  const create = Document.prototype.createElement;
  Document.prototype.createElement = function (this: Document, tagName: string, options?: ElementCreationOptions) {
    const el = create.call(this, tagName, options);
    if (tagName.toLowerCase() === "style") el.setAttribute("nonce", nonce);
    return el;
  } as typeof Document.prototype.createElement;
}

export {};
