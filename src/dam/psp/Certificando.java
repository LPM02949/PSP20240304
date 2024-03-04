package dam.psp;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Certificando implements Runnable {
	Socket sCliente;
	DataInputStream in;

	public Certificando(Socket socket) {
		this.sCliente = socket;
		try {
			in = new DataInputStream(sCliente.getInputStream());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void run() {
		try {
			String peticion = in.readUTF();
			System.out.println("Peticion de " + sCliente.getRemoteSocketAddress() + ": " + peticion);
			switch (peticion) {
			case "hash":
				secuenciaBytes();
				break;
			case "cert":
				almacenarCertificado();
				break;
			case "cifrar":
				cifrar();
				break;
			default:
				enviarRespuesta("ERROR:'" + peticion + "' no se reconoce como una petición válida");
			}
		} catch (EOFException e) {
			enviarRespuesta("ERROR:Se esperaba una petición");
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				sCliente.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	void secuenciaBytes() {
		try {
			MessageDigest md;
			String algoritmo = in.readUTF();
			md = MessageDigest.getInstance(algoritmo);
			byte[] bytes = in.readAllBytes();
			if (bytes.length > 0) {
				String cadena = Base64.getEncoder().encodeToString(md.digest(bytes));
				enviarRespuesta("OK:" + cadena);
			} else
				enviarRespuesta("ERROR:Se esperaban datos");
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (EOFException e) {
			enviarRespuesta("ERROR:Se esperaba un algoritmo");
		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	void almacenarCertificado() {
		try {
			String alias = in.readUTF();
			try {
				String base = in.readUTF();
				CertificateFactory f = CertificateFactory.getInstance("X.509");
				byte[] byteEncoded = Base64.getDecoder().decode(base);
				Certificate cert = f.generateCertificate(new ByteArrayInputStream(byteEncoded));
				Servidor.ks.setCertificateEntry(alias, cert);
				MessageDigest md;
				md = MessageDigest.getInstance("SHA-256");
				md.update(base.getBytes());
				String cadena = Base64.getEncoder().encodeToString(md.digest());
				enviarRespuesta("OK:" + cadena);
			} catch (CertificateException e) {
			} catch (IllegalArgumentException e) {
				enviarRespuesta("ERROR:Se esperaba Base64");
			} catch (EOFException e) {
				enviarRespuesta("ERROR:Se esperaba un certificado");
			} catch (SocketTimeoutException e) {
				enviarRespuesta("ERROR:Read timed out");
			}
		} catch (EOFException e) {
			enviarRespuesta("ERROR:Se esperaba un alias");
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (IOException e) {
		} catch (KeyStoreException e) {
		} catch (NoSuchAlgorithmException e) {
		}
	}

	void cifrar() {
		String alias ="";
		try {
			alias = in.readUTF();
			Certificate cert = Servidor.ks.getCertificate(alias);
			if (cert == null)
				enviarRespuesta("ERROR:'" + alias + "' no es un certificado");
			else {
				Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				c.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
				int n;
				byte[] bloque = new byte[256];
				DataOutputStream out = new DataOutputStream(sCliente.getOutputStream());
				int contador = 0;
				try {
					while ((n = in.read(bloque)) != -1) {
						contador++;
						byte[] cifrado = c.doFinal(bloque, 0, n);
						out.writeUTF("OK:" + Base64.getEncoder().encodeToString(cifrado));
					}
					if (contador == 0) {
						enviarRespuesta("ERROR:Se esperaban datos");
					}
				} catch (SocketTimeoutException e) {
					enviarRespuesta("ERROR:Read timed out");
				}
			}
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (EOFException e) {
			enviarRespuesta("ERROR:Se esperaba un alias");
		} catch (IOException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			enviarRespuesta("ERROR:'" + alias + "' no contiene una clave RSA");
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}

	void enviarRespuesta(String respuesta) {
		try {
			new DataOutputStream(sCliente.getOutputStream()).writeUTF(respuesta);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}