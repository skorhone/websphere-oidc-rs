# websphere-oidc-rc
This library provides OpenID Connect Resource Server (RS) support for WebSphere Application Server (Classic and Liberty) using Trust Association Interceptor (TAI).

## Notes
Implementation currently supports only fixed keys.

## ResourceServerTAI (liberty)
Configuration is simple and straightforward. Just add following fragment to your server.xml:

	<trustAssociation id="oidcTrustAssociation"
		invokeForUnprotectedURI="false" failOverToAppAuthType="false">
		<interceptors id="oidcTAI" enabled="true"
			className="fi.kela.auth.was.oidc.ResourceServerTAI" invokeBeforeSSO="true"
			invokeAfterSSO="false" libraryRef="oidcTAI">
			<properties realm="myrealm" acceptedIssuer="https://myissuer" groupClaim="groupIds" signatureAlgorithm="HS256" secretKey="secret"/>
		</interceptors>
	</trustAssociation>

	<library id="oidcTAI" apiTypeVisibility="spec,ibm-api,api,third-party">
		<fileset dir="${mylibraries}" includes="websphere-oidc-rs-0.0.1-SNAPSHOT-jar-with-dependencies.jar" />
	</library>