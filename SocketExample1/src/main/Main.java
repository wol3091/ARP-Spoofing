package main;

import java.net.InetAddress;

public class Main {
	public static void main(String[] args) {

		InetAddress ip = null;
		try {
			ip = InetAddress.getByName("www.google.com");
			System.out.println("ȣ��Ʈ �ּ� : " + ip.getHostAddress());
			System.out.println("ȣ��Ʈ �̸� : " + ip.getHostName());
			System.out.println("�� �ּ� : "+ InetAddress.getLocalHost().getHostAddress());
			System.out.println("�� �̸� : "+ InetAddress.getLocalHost().getHostName());
		}catch(Exception e){
			e.printStackTrace();
		}
	}	
}
