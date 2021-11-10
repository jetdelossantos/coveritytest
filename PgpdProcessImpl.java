package com.aa.utils.pgpd.service.impl;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Iterator;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.aa.utils.pgpd.business.context.PgpdContext;
import com.aa.utils.pgpd.service.PgpdProcess;
import com.azure.identity.DefaultAzureCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.netfective.bluage.gapwalk.rt.call.ExecutionController;

@Service("com.aa.utils.pgpd.service.PgpdProcess")
public class PgpdProcessImpl implements PgpdProcess {

	private static final Logger LOGGER = LoggerFactory.getLogger(PgpdProcessImpl.class);

	@Override
	public void pgpd(PgpdContext ctx, ExecutionController ctrl) {
		final String NEWLINE = "#NEWLINE#";
		LOGGER.info("PGP decryption : Started");
		Map<String, Object> params = ctx.getParams();

		String ifilename = (String) params.get("IFILENAME");
		String ofilename = (String) params.get("OFILENAME");
		String dec_key = (String) params.getOrDefault("DEC_KEY", "dec.asc");
		String passwd = (String) params.getOrDefault("PASSWD","PASSWD");
		
		String azure_kv_endpoint = (String) params.getOrDefault("AZURE_KV_ENDPOINT","https://et-pas-kv-nonprod.vault.azure.net");
		String azure_storage_identity = (String) params.getOrDefault("AZURE_MANAGED_IDENTITY_CLIENT_ID", "AZURE_MANAGED_IDENTITY_CLIENT_ID");
		
		String accountIdentity = System.getenv(azure_storage_identity);
		
		try {
			DefaultAzureCredential defaultCredential = new DefaultAzureCredentialBuilder().managedIdentityClientId(accountIdentity).build();
			
	        SecretClient secretClient = new SecretClientBuilder()
	                .vaultUrl(azure_kv_endpoint)
	                .credential(defaultCredential)
	                .buildClient();
	        
	        KeyVaultSecret kvDec = secretClient.getSecret(dec_key);
	        
	        if(!StringUtils.isBlank(kvDec.getValue())) {
	        	String[] lines = kvDec.getValue().split(NEWLINE);
	        	try (PrintWriter out = new PrintWriter(dec_key)) {
					for (String line : lines) {
						if(line != null) {
							out.println(line.trim());	
						}
					}
				}
	        }
	        
	        KeyVaultSecret kvPwd = secretClient.getSecret(passwd);
	        
	        String decPwd = kvPwd.getValue();
	        
			Security.addProvider(new BouncyCastleProvider());
			//
			//Coverity Issue Changes (resource leak on an exceptional path)
			//
			FileInputStream ifile = new FileInputStream(ifilename);
			FileInputStream dkey = new FileInputStream(dec_key);
			
			InputStream in = new BufferedInputStream(ifile);
			InputStream keyIn = new BufferedInputStream(dkey);	
			
			decryptFile(in, keyIn, decPwd.toCharArray(), ofilename);
			
			keyIn.close();
			in.close();
			dkey.close();
			ifile.close();

			LOGGER.info("PGP Decrypted dec_key_file_name [" + dec_key + "]");
			LOGGER.info("PGP Decrypted filename [" + ifilename + "]");
			
			FileUtils.deleteQuietly(new File(dec_key));
		} catch (Exception e) {
			LOGGER.error(e.getMessage());
			ctx.setReturnCode(8);
			return;
		}
		
		LOGGER.info("PGP Encryption : Ended");
	}
        
	private static void decryptFile(InputStream in, InputStream keyIn, char[] passwd, String defaultFileName)
			throws IOException, NoSuchProviderException {
		in = PGPUtil.getDecoderStream(in);

		try {
			JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
			PGPEncryptedDataList enc;

			Object o = pgpF.nextObject();
			//
			// the first object might be a PGP marker packet.
			//
			if (o instanceof PGPEncryptedDataList) {
				enc = (PGPEncryptedDataList) o;
			} else {
				enc = (PGPEncryptedDataList) pgpF.nextObject();
			}

			//
			// find the secret key
			//
			Iterator it = enc.getEncryptedDataObjects();
			PGPPrivateKey sKey = null;
			PGPPublicKeyEncryptedData pbe = null;
			PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn),
					new JcaKeyFingerprintCalculator());

			while (sKey == null && it.hasNext()) {
				pbe = (PGPPublicKeyEncryptedData) it.next();

				sKey = PGPFileUtil.findSecretKey(pgpSec, pbe.getKeyID(), passwd);
			}

			if (sKey == null) {
				throw new IllegalArgumentException("secret key for message not found.");
			}

			InputStream clear = pbe
					.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

			JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

			PGPCompressedData cData = (PGPCompressedData) plainFact.nextObject();

			InputStream compressedStream = new BufferedInputStream(cData.getDataStream());
			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedStream);

			Object message = pgpFact.nextObject();

			if (message instanceof PGPLiteralData) {
				PGPLiteralData ld = (PGPLiteralData) message;
				
				String outFileName = defaultFileName;
				
				InputStream unc = ld.getInputStream();
				OutputStream fOut = new FileOutputStream(outFileName);

				Streams.pipeAll(unc, fOut);

				fOut.close();
			} else if (message instanceof PGPOnePassSignatureList) {
				throw new PGPException("encrypted message contains a signed message - not literal data.");
			} else {
				throw new PGPException("message is not a simple encrypted file - type unknown.");
			}

			if (pbe.isIntegrityProtected()) {
				if (!pbe.verify()) {
					LOGGER.warn("message failed integrity check");
				} else {
					LOGGER.info("message integrity check passed");
				}
			} else {
				LOGGER.warn("no message integrity check");
			}
		} catch (PGPException e) {
			LOGGER.error(e.getMessage(),e);
		}
	}

}
