/*
 * Kasuku - Open Source eUICC Remote Subscription Management Server
 * 
 * 
 * Copyright (C) 2019 - , Digital Solutions Ltd. - http://www.dsmagic.com
 *
 * Paul Bagyenda <bagyenda@dsmagic.com>
 * 
 * This program is free software, distributed under the terms of
 * the GNU General Public License.
 */ 

/**
 * This class file was automatically generated by jASN1 v1.6.0 (http://www.openmuc.org)
 */

package io.njiwa.dp.pedefinitions;

import org.openmuc.jasn1.ber.BerByteArrayOutputStream;
import org.openmuc.jasn1.ber.BerIdentifier;
import org.openmuc.jasn1.ber.BerLength;
import org.openmuc.jasn1.ber.types.BerOctetString;

import java.io.IOException;
import java.io.InputStream;


public class PECDMAParameter {

	public static final BerIdentifier identifier = new BerIdentifier(BerIdentifier.UNIVERSAL_CLASS, BerIdentifier.CONSTRUCTED, 16);
	protected BerIdentifier id;

	public byte[] code = null;
	private PEHeader cdmaHeader = null;

	private BerOctetString authenticationKey = null;

	private BerOctetString ssd = null;

	private BerOctetString hrpdAccessAuthenticationData = null;

	private BerOctetString simpleIPAuthenticationData = null;

	private BerOctetString mobileIPAuthenticationData = null;

	public PECDMAParameter() {
		id = identifier;
	}

	public PECDMAParameter(byte[] code) {
		id = identifier;
		this.code = code;
	}

	public void setCdmaHeader(PEHeader cdmaHeader) {
		this.cdmaHeader = cdmaHeader;
	}

	public PEHeader getCdmaHeader() {
		return cdmaHeader;
	}

	public void setAuthenticationKey(BerOctetString authenticationKey) {
		this.authenticationKey = authenticationKey;
	}

	public BerOctetString getAuthenticationKey() {
		return authenticationKey;
	}

	public void setSsd(BerOctetString ssd) {
		this.ssd = ssd;
	}

	public BerOctetString getSsd() {
		return ssd;
	}

	public void setHrpdAccessAuthenticationData(BerOctetString hrpdAccessAuthenticationData) {
		this.hrpdAccessAuthenticationData = hrpdAccessAuthenticationData;
	}

	public BerOctetString getHrpdAccessAuthenticationData() {
		return hrpdAccessAuthenticationData;
	}

	public void setSimpleIPAuthenticationData(BerOctetString simpleIPAuthenticationData) {
		this.simpleIPAuthenticationData = simpleIPAuthenticationData;
	}

	public BerOctetString getSimpleIPAuthenticationData() {
		return simpleIPAuthenticationData;
	}

	public void setMobileIPAuthenticationData(BerOctetString mobileIPAuthenticationData) {
		this.mobileIPAuthenticationData = mobileIPAuthenticationData;
	}

	public BerOctetString getMobileIPAuthenticationData() {
		return mobileIPAuthenticationData;
	}

	public int encode(BerByteArrayOutputStream os, boolean explicit) throws IOException {

		int codeLength;

		if (code != null) {
			codeLength = code.length;
			for (int i = code.length - 1; i >= 0; i--) {
				os.write(code[i]);
			}
		}
		else {
			codeLength = 0;
			if (mobileIPAuthenticationData != null) {
				codeLength += mobileIPAuthenticationData.encode(os, false);
				// write tag: CONTEXT_CLASS, PRIMITIVE, 5
				os.write(0x85);
				codeLength += 1;
			}
			
			if (simpleIPAuthenticationData != null) {
				codeLength += simpleIPAuthenticationData.encode(os, false);
				// write tag: CONTEXT_CLASS, PRIMITIVE, 4
				os.write(0x84);
				codeLength += 1;
			}
			
			if (hrpdAccessAuthenticationData != null) {
				codeLength += hrpdAccessAuthenticationData.encode(os, false);
				// write tag: CONTEXT_CLASS, PRIMITIVE, 3
				os.write(0x83);
				codeLength += 1;
			}
			
			if (ssd != null) {
				codeLength += ssd.encode(os, false);
				// write tag: CONTEXT_CLASS, PRIMITIVE, 2
				os.write(0x82);
				codeLength += 1;
			}
			
			codeLength += authenticationKey.encode(os, false);
			// write tag: CONTEXT_CLASS, PRIMITIVE, 1
			os.write(0x81);
			codeLength += 1;
			
			codeLength += cdmaHeader.encode(os, false);
			// write tag: CONTEXT_CLASS, CONSTRUCTED, 0
			os.write(0xa0);
			codeLength += 1;
			
			codeLength += BerLength.encodeLength(os, codeLength);
		}

		if (explicit) {
			codeLength += id.encode(os);
		}

		return codeLength;

	}

	public int decode(InputStream is, boolean explicit) throws IOException {
		int codeLength = 0;
		int subCodeLength = 0;
		BerIdentifier berIdentifier = new BerIdentifier();

		if (explicit) {
			codeLength += id.decodeAndCheck(is);
		}

		BerLength length = new BerLength();
		codeLength += length.decode(is);

		int totalLength = length.val;
		codeLength += totalLength;

		subCodeLength += berIdentifier.decode(is);
		if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 0)) {
			cdmaHeader = new PEHeader();
			subCodeLength += cdmaHeader.decode(is, false);
			subCodeLength += berIdentifier.decode(is);
		}
		else {
			throw new IOException("Identifier does not match the mandatory sequence element identifer.");
		}
		
		if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.PRIMITIVE, 1)) {
			authenticationKey = new BerOctetString();
			subCodeLength += authenticationKey.decode(is, false);
			if (subCodeLength == totalLength) {
				return codeLength;
			}
			subCodeLength += berIdentifier.decode(is);
		}
		else {
			throw new IOException("Identifier does not match the mandatory sequence element identifer.");
		}
		
		if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.PRIMITIVE, 2)) {
			ssd = new BerOctetString();
			subCodeLength += ssd.decode(is, false);
			if (subCodeLength == totalLength) {
				return codeLength;
			}
			subCodeLength += berIdentifier.decode(is);
		}
		
		if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.PRIMITIVE, 3)) {
			hrpdAccessAuthenticationData = new BerOctetString();
			subCodeLength += hrpdAccessAuthenticationData.decode(is, false);
			if (subCodeLength == totalLength) {
				return codeLength;
			}
			subCodeLength += berIdentifier.decode(is);
		}
		
		if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.PRIMITIVE, 4)) {
			simpleIPAuthenticationData = new BerOctetString();
			subCodeLength += simpleIPAuthenticationData.decode(is, false);
			if (subCodeLength == totalLength) {
				return codeLength;
			}
			subCodeLength += berIdentifier.decode(is);
		}
		
		if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.PRIMITIVE, 5)) {
			mobileIPAuthenticationData = new BerOctetString();
			subCodeLength += mobileIPAuthenticationData.decode(is, false);
			if (subCodeLength == totalLength) {
				return codeLength;
			}
		}
		throw new IOException("Unexpected end of sequence, length tag: " + totalLength + ", actual sequence length: " + subCodeLength);

		
	}

	public void encodeAndSave(int encodingSizeGuess) throws IOException {
		BerByteArrayOutputStream os = new BerByteArrayOutputStream(encodingSizeGuess);
		encode(os, false);
		code = os.getArray();
	}

	public String toString() {
		StringBuilder sb = new StringBuilder("SEQUENCE{");
		sb.append("cdmaHeader: ").append(cdmaHeader);
		
		sb.append(", ");
		sb.append("authenticationKey: ").append(authenticationKey);
		
		if (ssd != null) {
			sb.append(", ");
			sb.append("ssd: ").append(ssd);
		}
		
		if (hrpdAccessAuthenticationData != null) {
			sb.append(", ");
			sb.append("hrpdAccessAuthenticationData: ").append(hrpdAccessAuthenticationData);
		}
		
		if (simpleIPAuthenticationData != null) {
			sb.append(", ");
			sb.append("simpleIPAuthenticationData: ").append(simpleIPAuthenticationData);
		}
		
		if (mobileIPAuthenticationData != null) {
			sb.append(", ");
			sb.append("mobileIPAuthenticationData: ").append(mobileIPAuthenticationData);
		}
		
		sb.append("}");
		return sb.toString();
	}

}
