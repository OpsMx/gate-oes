FROM quay.io/opsmxpublic/ubifips:8.7
#FROM registry.access.redhat.com/ubi8/ubi-minimal:8.7 as java-base
MAINTAINER sig-platform@spinnaker.io
COPY ./gate-web/build/install/gate /opt/gate
RUN yum -y install java-17-openjdk-devel wget vim curl net-tools nettle
RUN yum -y update
RUN adduser spinnaker
RUN mkdir -p /opt/gate/plugins && mkdir -p /opt/spinnaker/plugins
RUN chown -R spinnaker:spinnaker /opt/spinnaker

RUN chmod -R 777 /opt/gate/plugins/
RUN chown -R spinnaker:spinnaker /opt/
USER spinnaker
CMD ["/opt/gate/bin/gate"]
