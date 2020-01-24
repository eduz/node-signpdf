"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
Object.defineProperty(exports, "SignPdfError", {
  enumerable: true,
  get: function () {
    return _SignPdfError.default;
  }
});
exports.default = exports.SignPdf = exports.DEFAULT_BYTE_RANGE_PLACEHOLDER = void 0;

var _nodeForge = _interopRequireDefault(require("node-forge"));

var _SignPdfError = _interopRequireDefault(require("./SignPdfError"));

var _helpers = require("./helpers");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/* eslint-disable block-scoped-var */

/* eslint-disable no-redeclare */

/* eslint-disable no-var */

/* eslint-disable vars-on-top */

/* eslint-disable no-undef */

/* eslint-disable no-unused-vars */

/* eslint-disable import/no-unresolved */

/* eslint-disable global-require */
const os = require('os');

if (os.platform() === 'win32') {
  if (os.arch() === 'ia32') {
    var chilkat = require('@chilkat/ck-node10-win-ia32');
  } else {
    var chilkat = require('@chilkat/ck-node10-win64');
  }
} else if (os.platform() === 'linux') {
  if (os.arch() === 'arm') {
    var chilkat = require('@chilkat/ck-node10-arm');
  } else if (os.arch() === 'x86') {
    var chilkat = require('@chilkat/ck-node10-linux32');
  } else {
    var chilkat = require('@chilkat/ck-node10-linux64');
  }
} else if (os.platform() === 'darwin') {
  var chilkat = require('@chilkat/ck-node10-macosx');
}

const DEFAULT_BYTE_RANGE_PLACEHOLDER = '**********';
exports.DEFAULT_BYTE_RANGE_PLACEHOLDER = DEFAULT_BYTE_RANGE_PLACEHOLDER;

class SignPdf {
  constructor() {
    this.byteRangePlaceholder = DEFAULT_BYTE_RANGE_PLACEHOLDER;
    this.lastSignature = null;
  }

  sign(pdfBuffer, p12Buffer, additionalOptions = {}) {
    const options = {
      asn1StrictParsing: false,
      passphrase: '',
      ...additionalOptions
    };

    if (!(pdfBuffer instanceof Buffer)) {
      throw new _SignPdfError.default('PDF expected as Buffer.', _SignPdfError.default.TYPE_INPUT);
    }

    if (!(p12Buffer instanceof Buffer)) {
      throw new _SignPdfError.default('p12 certificate expected as Buffer.', _SignPdfError.default.TYPE_INPUT);
    }

    let pdf = (0, _helpers.removeTrailingNewLine)(pdfBuffer); // Find the ByteRange placeholder.

    const byteRangePlaceholder = [0, `/${this.byteRangePlaceholder}`, `/${this.byteRangePlaceholder}`, `/${this.byteRangePlaceholder}`];
    const byteRangeString = `/ByteRange [${byteRangePlaceholder.join(' ')}]`;
    const byteRangePos = pdf.indexOf(byteRangeString);

    if (byteRangePos === -1) {
      throw new _SignPdfError.default(`Could not find ByteRange placeholder: ${byteRangeString}`, _SignPdfError.default.TYPE_PARSE);
    } // Calculate the actual ByteRange that needs to replace the placeholder.


    const byteRangeEnd = byteRangePos + byteRangeString.length;
    const contentsTagPos = pdf.indexOf('/Contents ', byteRangeEnd);
    const placeholderPos = pdf.indexOf('<', contentsTagPos);
    const placeholderEnd = pdf.indexOf('>', placeholderPos);
    const placeholderLengthWithBrackets = placeholderEnd + 1 - placeholderPos;
    const placeholderLength = placeholderLengthWithBrackets - 2;
    const byteRange = [0, 0, 0, 0];
    byteRange[1] = placeholderPos;
    byteRange[2] = byteRange[1] + placeholderLengthWithBrackets;
    byteRange[3] = pdf.length - byteRange[2];
    let actualByteRange = `/ByteRange [${byteRange.join(' ')}]`;
    actualByteRange += ' '.repeat(byteRangeString.length - actualByteRange.length); // Replace the /ByteRange placeholder with the actual ByteRange

    pdf = Buffer.concat([pdf.slice(0, byteRangePos), Buffer.from(actualByteRange), pdf.slice(byteRangeEnd)]); // Remove the placeholder signature

    pdf = Buffer.concat([pdf.slice(0, byteRange[1]), pdf.slice(byteRange[2], byteRange[2] + byteRange[3])]); // Convert Buffer P12 to a forge implementation.

    const forgeCert = _nodeForge.default.util.createBuffer(p12Buffer.toString('binary'));

    const p12Asn1 = _nodeForge.default.asn1.fromDer(forgeCert);

    const p12 = _nodeForge.default.pkcs12.pkcs12FromAsn1(p12Asn1, options.asn1StrictParsing, options.passphrase); // Extract safe bags by type.
    // We will need all the certificates and the private key.


    const certBags = p12.getBags({
      bagType: _nodeForge.default.pki.oids.certBag
    })[_nodeForge.default.pki.oids.certBag];

    const keyBags = p12.getBags({
      bagType: _nodeForge.default.pki.oids.pkcs8ShroudedKeyBag
    })[_nodeForge.default.pki.oids.pkcs8ShroudedKeyBag];

    const privateKey = keyBags[0].key; // Here comes the actual PKCS#7 signing.

    const p7 = _nodeForge.default.pkcs7.createSignedData(); // Start off by setting the content.


    p7.content = _nodeForge.default.util.createBuffer(pdf.toString('binary')); // Then add all the certificates (-cacerts & -clcerts)
    // Keep track of the last found client certificate.
    // This will be the public key that will be bundled in the signature.

    let certificate;
    Object.keys(certBags).forEach(i => {
      const {
        publicKey
      } = certBags[i].cert;
      p7.addCertificate(certBags[i].cert); // Try to find the certificate that matches the private key.

      if (privateKey.n.compareTo(publicKey.n) === 0 && privateKey.e.compareTo(publicKey.e) === 0) {
        certificate = certBags[i].cert;
      }
    });

    if (typeof certificate === 'undefined') {
      throw new _SignPdfError.default('Failed to find a certificate that matches the private key.', _SignPdfError.default.TYPE_INPUT);
    } // Add a sha256 signer. That's what Adobe.PPKLite adbe.pkcs7.detached expects.


    p7.addSigner({
      key: privateKey,
      certificate,
      digestAlgorithm: _nodeForge.default.pki.oids.sha256,
      authenticatedAttributes: [{
        type: _nodeForge.default.pki.oids.contentType,
        value: _nodeForge.default.pki.oids.data
      }, {
        type: _nodeForge.default.pki.oids.messageDigest // value will be auto-populated at signing time

      }, {
        type: _nodeForge.default.pki.oids.signingTime,
        // value can also be auto-populated at signing time
        // We may also support passing this as an option to sign().
        // Would be useful to match the creation time of the document for example.
        value: new Date()
      }]
    }); // Sign in detached mode.

    p7.sign({
      detached: true
    }); // Check if the PDF has a good enough placeholder to fit the signature.

    const raw = _nodeForge.default.asn1.toDer(p7.toAsn1()).getBytes(); // placeholderLength represents the length of the HEXified symbols but we're
    // checking the actual lengths.


    if (raw.length * 2 > placeholderLength) {
      throw new _SignPdfError.default(`Signature exceeds placeholder length: ${raw.length * 2} > ${placeholderLength}`, _SignPdfError.default.TYPE_INPUT);
    }

    let signature = Buffer.from(raw, 'binary').toString('hex'); // Store the HEXified signature. At least useful in tests.

    this.lastSignature = signature; // Pad the signature with zeroes so the it is the same length as the placeholder

    signature += Buffer.from(String.fromCharCode(0).repeat(placeholderLength / 2 - raw.length)).toString('hex'); // Place it in the document.

    pdf = Buffer.concat([pdf.slice(0, byteRange[1]), Buffer.from(`<${signature}>`), pdf.slice(byteRange[1])]); // Magic. Done.

    return pdf;
  }

  signPadesICPBrasil(pdfBuffer, p12Buffer, additionalOptions = {}) {
    const options = {
      asn1StrictParsing: false,
      passphrase: '',
      ...additionalOptions
    };

    if (!(pdfBuffer instanceof Buffer)) {
      throw new _SignPdfError.default('PDF expected as Buffer.', _SignPdfError.default.TYPE_INPUT);
    }

    if (!(p12Buffer instanceof Buffer)) {
      throw new _SignPdfError.default('p12 certificate expected as Buffer.', _SignPdfError.default.TYPE_INPUT);
    }

    let pdf = (0, _helpers.removeTrailingNewLine)(pdfBuffer); // Find the ByteRange placeholder.

    const byteRangePlaceholder = [0, `/${this.byteRangePlaceholder}`, `/${this.byteRangePlaceholder}`, `/${this.byteRangePlaceholder}`];
    const byteRangeString = `/ByteRange [${byteRangePlaceholder.join(' ')}]`;
    const byteRangePos = pdf.indexOf(byteRangeString);

    if (byteRangePos === -1) {
      throw new _SignPdfError.default(`Could not find ByteRange placeholder: ${byteRangeString}`, _SignPdfError.default.TYPE_PARSE);
    } // Calculate the actual ByteRange that needs to replace the placeholder.


    const byteRangeEnd = byteRangePos + byteRangeString.length;
    const contentsTagPos = pdf.indexOf('/Contents ', byteRangeEnd);
    const placeholderPos = pdf.indexOf('<', contentsTagPos);
    const placeholderEnd = pdf.indexOf('>', placeholderPos);
    const placeholderLengthWithBrackets = placeholderEnd + 1 - placeholderPos;
    const placeholderLength = placeholderLengthWithBrackets - 2;
    const byteRange = [0, 0, 0, 0];
    byteRange[1] = placeholderPos;
    byteRange[2] = byteRange[1] + placeholderLengthWithBrackets;
    byteRange[3] = pdf.length - byteRange[2];
    let actualByteRange = `/ByteRange [${byteRange.join(' ')}]`;
    actualByteRange += ' '.repeat(byteRangeString.length - actualByteRange.length); // Replace the /ByteRange placeholder with the actual ByteRange

    pdf = Buffer.concat([pdf.slice(0, byteRangePos), Buffer.from(actualByteRange), pdf.slice(byteRangeEnd)]); // Remove the placeholder signature

    pdf = Buffer.concat([pdf.slice(0, byteRange[1]), pdf.slice(byteRange[2], byteRange[2] + byteRange[3])]); // Initiate chilkat

    const glob = new chilkat.Global();
    let success = glob.UnlockBundle(process.env.CHILKAT_LICENSE ? process.env.CHILKAT_LICENSE : 'Anything for 30-day trial');

    if (success !== true) {
      // console.log(glob.LastErrorText);
      return;
    }

    const crypt = new chilkat.Crypt2();
    const cert = new chilkat.Cert();
    success = cert.LoadPfxData(p12Buffer, options.passphrase);

    if (success !== true) {
      // console.log(cert.LastErrorText);
      return;
    }

    crypt.SetSigningCert(cert);
    crypt.HashAlgorithm = 'sha256'; // Create JSON to indicate which signing attributes to include.

    const attrs = new chilkat.JsonObject();
    attrs.UpdateBool('contentType', true);
    attrs.UpdateBool('signingTime', true);
    attrs.UpdateBool('messageDigest', true);
    attrs.UpdateString('contentHint.text', 'Content-Type: application/octet-stream\r\nContent-Disposition: attachment;filename="documento.pdf"');
    attrs.UpdateString('contentHint.oid', '1.2.840.113549.1.7.1');
    attrs.UpdateString('policyId.id', '2.16.76.1.7.1.11.1.1');
    attrs.UpdateString('policyId.hash', 'RPxYFustcF2MjwIqf5Oz+0nt+uGnuRSe9vq4M+m7Y/g=');
    attrs.UpdateString('policyId.hashAlg', 'SHA256');
    attrs.UpdateString('policyId.uri', 'http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_1.der');
    attrs.UpdateBool('signingCertificateV2', true);
    crypt.SigningAttributes = attrs.Emit();
    const bufSig = crypt.SignBytes(pdf); // Check if the PDF has a good enough placeholder to fit the signature.
    // placeholderLength represents the length of the HEXified symbols but we're
    // checking the actual lengths.

    if (bufSig.length * 2 > placeholderLength) {
      throw new _SignPdfError.default(`Signature exceeds placeholder length: ${bufSig.length * 2} > ${placeholderLength}`, _SignPdfError.default.TYPE_INPUT);
    }

    let signature = bufSig.toString('hex'); // Store the HEXified signature. At least useful in tests.

    this.lastSignature = signature; // Pad the signature with zeroes so the it is the same length as the placeholder

    signature += Buffer.from(String.fromCharCode(0).repeat(placeholderLength / 2 - bufSig.length)).toString('hex'); // Place it in the document.

    pdf = Buffer.concat([pdf.slice(0, byteRange[1]), Buffer.from(`<${signature}>`), pdf.slice(byteRange[1])]); // Magic. Done.
    // eslint-disable-next-line consistent-return

    return pdf;
  }

  signCadesICPBrasil(pdfBuffer, p12Buffer, additionalOptions = {}) {
    const options = {
      asn1StrictParsing: false,
      passphrase: '',
      ...additionalOptions
    };

    if (!(pdfBuffer instanceof Buffer)) {
      throw new _SignPdfError.default('File expected as Buffer.', _SignPdfError.default.TYPE_INPUT);
    }

    if (!(p12Buffer instanceof Buffer)) {
      throw new _SignPdfError.default('p12 certificate expected as Buffer.', _SignPdfError.default.TYPE_INPUT);
    } // Initiate chilkat


    const glob = new chilkat.Global();
    let success = glob.UnlockBundle(process.env.CHILKAT_LICENSE ? process.env.CHILKAT_LICENSE : 'Anything for 30-day trial');

    if (success !== true) {
      // console.log(glob.LastErrorText);
      return;
    }

    const crypt = new chilkat.Crypt2();
    const cert = new chilkat.Cert();
    success = cert.LoadPfxData(p12Buffer, options.passphrase);

    if (success !== true) {
      // console.log(cert.LastErrorText);
      return;
    }

    crypt.SetSigningCert(cert);
    crypt.HashAlgorithm = 'sha256'; // Create JSON to indicate which signing attributes to include.

    const attrs = new chilkat.JsonObject();
    attrs.UpdateBool('contentType', true);
    attrs.UpdateBool('signingTime', true);
    attrs.UpdateBool('messageDigest', true);
    attrs.UpdateString('contentHint.text', 'Content-Type: application/octet-stream\r\nContent-Disposition: attachment;filename="documento.pdf"');
    attrs.UpdateString('contentHint.oid', '1.2.840.113549.1.7.1');
    attrs.UpdateString('policyId.id', '2.16.76.1.7.1.1.2.3');
    attrs.UpdateString('policyId.hash', 'sW6Iu/dzIqZ5lbeQeHeO09DqfIhYe29tUYtxXo92o9U=');
    attrs.UpdateString('policyId.hashAlg', 'SHA256');
    attrs.UpdateString('policyId.uri', 'http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_3.der');
    attrs.UpdateBool('signingCertificateV2', true);
    crypt.SigningAttributes = attrs.Emit();
    const bufSig = crypt.SignBytes(pdfBuffer); // eslint-disable-next-line consistent-return

    return bufSig;
  }

}

exports.SignPdf = SignPdf;

var _default = new SignPdf();

exports.default = _default;