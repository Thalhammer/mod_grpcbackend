# mod_grpcbackend

This module provides a way for apache to directly interact with a grpc backend service. Using this you can add a webinterface to your grpc service without any additional libraries or complex configuration.

### Configuration

Currently mod_grpcbackend provides only 4 configuration directives, but only 2 are required for a working configuration.

##### GrpcEnabled Directive

If you want a directory to be handled by a grpc backend, you need to set this directive to on.

##### GrpcHost Directive

This allows you to set the grpc service host and port apache will forward your requests to.

##### GrpcConnectTimeout Directive

This optional directive allows you to set a timeout in milliseconds for connecting to your backend service.

##### GrpcCallTimeout Directive

This optional directive allows you to set a timeout in milliseconds for each call to your backend service.

