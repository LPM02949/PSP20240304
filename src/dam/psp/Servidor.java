package dam.psp;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Servidor {

	static KeyStore ks;

	public static void main(String[] args) throws NoSuchAlgorithmException, CertificateException {

		ExecutorService executor = Executors.newFixedThreadPool(100);
		try (ServerSocket sSocket = new ServerSocket(9000)) {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(null);
			System.out.println("Servidor funcionando en el puerto 9000");

			while (true) {

				System.out.println("Espero clientes");
				Socket sCliente = sSocket.accept();
				System.out.println("Cliente conectado: " + sCliente.getInetAddress().toString());
				sCliente.setSoTimeout(3000);
				executor.execute(new Certificando(sCliente));

			}

		} catch (KeyStoreException e) {
			e.printStackTrace();

		} catch (IOException e1) {
			e1.printStackTrace();

		}

	}

}