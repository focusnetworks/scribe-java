package org.scribe.examples;

import java.util.Scanner;

import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.TwitterApi;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.oauth.OAuthService;

public class TwitterExample {
	private static final String PROTECTED_RESOURCE_URL = "http://api.twitter.com/1.1/followers/list" + ".json";
	private static final String apiKey = "0r1zVtud6Mrwhuu8fZamGg";
	private static final String apiSecret = "2XCKWwmm6UtDzsvKhYfMdWQaWduLQoIZyRYJlniyrs";
	private static final String callback = "http://focusnetworks.com.br/test";
	private static final String consumerKey = "0r1zVtud6Mrwhuu8fZamGg";

	public static void main(String[] args) {
		// If you choose to use a callback, "oauth_verifier" will be the return value by Twitter (request param)
		OAuthService service = new ServiceBuilder().provider(TwitterApi.class)
		// .apiKey("6icbcAXyZx67r8uTAUM5Qw")
		// .apiSecret("SCCAdUUc6LXxiazxH3N0QfpNUvlUy84mZ2XZKiv39s")
				.apiKey(apiKey).apiSecret(apiSecret).callback(callback).build();
		Scanner in = new Scanner(System.in);

		System.out.println("=== Twitter's OAuth Workflow ===");
		System.out.println();

		// Obtain the Request Token
		System.out.println("Fetching the Request Token...");
		Token requestToken = service.getRequestToken();
		System.out.println("Got the Request Token!");
		System.out.println();

		System.out.println("Now go and authorize Scribe here:");
		System.out.println(service.getAuthorizationUrl(requestToken));
		System.out.println("And paste the verifier here");
		System.out.print(">>");
		String strToken = in.nextLine();
		String strVerifier = in.nextLine();
		System.out.println();

		// Trade the Request Token and Verfier for the Access Token
		System.out.println("Trading the Request Token for an Access Token...");
		// Token accessToken = service.getAccessToken(requestToken, verifier);
		requestToken = new Token(strToken, consumerKey );
		Verifier verifier = new Verifier(strVerifier);

		Token accessToken = service.getAccessToken(requestToken, verifier);

		System.out.println("Got the Access Token!");
		System.out.println("(if your curious it looks like this: " + accessToken + " )");
		System.out.println();

		// Now let's go and ask for a protected resource!
		System.out.println("Now we're going to access a protected resource...");
		OAuthRequest request = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL);
		// request.addBodyParameter("status", "this is sparta! *");
		service.signRequest(accessToken, request);
		Response response = request.send();
		System.out.println("Got it! Lets see what we found...");
		System.out.println();
		System.out.println(response.getBody());

		System.out.println();
		System.out.println("Thats it man! Go and build something awesome with Scribe! :)");
	}

//	public static void main(String[] args) {
//		Scanner in = new Scanner(System.in);
//		OAuthService service = new ServiceBuilder().provider(TwitterApi.class).apiKey(apiKey).apiSecret(apiSecret).callback(callback).build();
//		System.out.println("oauth_verifier");
//		String code = in.nextLine();
//		System.out.println("Verifier :: " + code);
//		System.out.println("service.getRequestToken()" + service.getRequestToken());
//		session = request.getSession(false);
//		Token requestToken = (Token) session.getAttribute("TOKEN");
//		System.out.println("requestToken from Session " + service.getRequestToken().getToken() + " Secr" + service.getRequestToken().getSecret());
//		if (code != null && !code.isEmpty()) {
//			System.out.println("Inside code != null Condition");
//			Verifier verifier = new Verifier(code);
//			Token accessToken = service.getAccessToken(requestToken, verifier);
//			OAuthRequest req = new OAuthRequest(Verb.GET, OAUTH_PROTECTED_URL);
//			service.signRequest(accessToken, req);
//			Response res = req.send();
//			response.setContentType("text/plain");
//			response.getWriter().println(res.getBody());
//		}
//	}

}