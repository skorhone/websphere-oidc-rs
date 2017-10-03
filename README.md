# websphere-oic-rc
This library provides Trust Association Interceptor (TAI) based implementation of OpenID Connect Resource Server (RS) provider for WebSphere Application Server (Classic and Liberty)

## Notes
Implementation currently supports only HMAC256 (shared secret) based signature verification. 

## ResourceServerTAI (liberty)
Configuration is simple and straightforward. Just add following fragment to your server.xml:

	<trustAssociation id="oicTrustAssociation"
		invokeForUnprotectedURI="false" failOverToAppAuthType="false">
		<interceptors id="oicTAI" enabled="true"
			className="fi.kela.auth.was.oic.ResourceServerTAI" invokeBeforeSSO="true"
			invokeAfterSSO="false" libraryRef="oicTAI">
			<properties realm="myrealm" acceptedIssuer="https://myissuer" groupClaim="groupIds" secretKey="secret"/>
		</interceptors>
	</trustAssociation>

	<library id="oicTAI" apiTypeVisibility="spec,ibm-api,api,third-party">
		<fileset dir="${mylibraries}" includes="websphere-oic-rs-0.0.1-SNAPSHOT-jar-with-dependencies.jar" />
	</library>