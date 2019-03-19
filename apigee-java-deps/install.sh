mvn install:install-file \
  -Dfile=expressions-1.0.0.jar \
  -DgroupId=com.apigee.edge \
  -DartifactId=expressions \
  -Dversion=1.0.0 \
  -Dpackaging=jar \
  -DgeneratePom=true

mvn install:install-file \
  -Dfile=message-flow-1.0.0.jar \
  -DgroupId=com.apigee.edge \
  -DartifactId=message-flow \
  -Dversion=1.0.0 \
  -Dpackaging=jar \
  -DgeneratePom=true
