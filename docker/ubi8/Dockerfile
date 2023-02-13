FROM quay.io/opsmxpublic/ubi8-jre-11:v1
MAINTAINER sig-platform@spinnaker.io
COPY ./gate-web/build/install/gate /opt/gate
RUN yum -y install java-11-openjdk-headless.x86_64 wget vim curl net-tools nettle
RUN yum -y update
RUN adduser spinnaker
RUN mkdir -p /opt/gate/plugins && mkdir -p /opt/spinnaker/plugins 
RUN chown -R spinnaker:spinnaker /opt/spinnaker
RUN chmod -R 777 /opt/gate/plugins/
RUN chown -R spinnaker:spinnaker /opt/
USER spinnaker
CMD ["/opt/gate/bin/gate"]
