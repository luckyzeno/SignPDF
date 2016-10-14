import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
 
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.LtvVerification;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;
 
public class SignPDF {
 
	public void sign(String src, String key, float signX, float signY, float signWith, float signHeight, int signP)
					throws GeneralSecurityException, IOException, DocumentException {
		char [] pass ="Jylc168123456".toCharArray();
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance("pkcs12");
		ks.load(new FileInputStream(key), pass);
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, pass);
        Certificate[] chain = ks.getCertificateChain(alias);
        String tsaUrl = "http://timestamp.wosign.com/rfc3161";
        TSAClient tsa = new TSAClientBouncyCastle(tsaUrl);
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
		String dest = src+".tmp";
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason("文档保护");
        appearance.setLocation("企业签章");
        appearance.setLayer2Text("");
        appearance.setSignatureCreator("JYLC168");
        appearance.setVisibleSignature(new Rectangle(signX, signY, signX+signWith, signY+signHeight), signP, "sig");
        // Creating the signature
        ExternalSignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, provider.getName());
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, tsa, 0, CryptoStandard.CMS);
        reader.close();
        os.close();
        // Enable LTV
        PdfReader r = new PdfReader(dest);
        FileOutputStream fos = new FileOutputStream(src);
        PdfStamper stp = new PdfStamper(r,fos,'\0',true);
        LtvVerification v = stp.getLtvVerification();
		v.addVerification("sig", null, new CrlClientOnline(), LtvVerification.CertificateOption.WHOLE_CHAIN, LtvVerification.Level.OCSP_CRL, LtvVerification.CertificateInclusion.NO);
		stp.close();
		r.close();
		//删除临时文件
		File tmp = new File(dest);
		if(tmp.exists()){
			tmp.delete();
		}
	}
	
 
	public static void main(String[] args) throws IOException, GeneralSecurityException, DocumentException {
		if(args.length<7){
			throw new IOException("args error");
		}
		String src = args[0];
		String key = args[1];
		float signX = Float.parseFloat(args[2]);
		float signY = Float.parseFloat(args[3]);
		float signWith = Float.parseFloat(args[4]);
		float signHeight = Float.parseFloat(args[5]);
		int signP = Integer.parseInt(args[6]);
        SignPDF app = new SignPDF();
        app.sign(src, key, signX, signY, signWith, signHeight, signP);
	}
}