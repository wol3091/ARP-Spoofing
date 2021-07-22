package main;

import java.net.InetAddress;

public class Main {
	public static void main(String[] args) {

		InetAddress ip = null;
		try {
			ip = InetAddress.getByName("www.google.com");
			System.out.println("호스트 주소 : " + ip.getHostAddress());
			System.out.println("호스트 이름 : " + ip.getHostName());
			System.out.println("내 주소 : "+ InetAddress.getLocalHost().getHostAddress());
			System.out.println("내 이름 : "+ InetAddress.getLocalHost().getHostName());
		}catch(Exception e){
			e.printStackTrace();
		}
	}	
}
