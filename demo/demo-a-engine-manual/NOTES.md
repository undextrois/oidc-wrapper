
KEYCLOAK
testuser / password123

HOW TO RUN THE DEMO A 

APP_PORT=7001 REDIRECT_URI=http://localhost:7001/auth/callback POST_LOGOUT_REDIRECT_URI=http://localhost:7001/ mvn compile exec:java

export APP_PORT=7001
export REDIRECT_URI=http://localhost:7001/auth/callback
export POST_LOGOUT_REDIRECT_URI=http://localhost:7001/
mvn compile exec:java

curl -i --cookie "SESSION=MFXyn0dhuFhDfDnawJG9R6RLpFmZ0p7XPDMxLfowmvs" http://localhost:7001/auth/me

MFXyn0dhuFhDfDnawJG9R6RLpFmZ0p7XPDMxLfowmvs
