APACHECTL=apachectl
PROTOSRC = $(shell find . -name '*.proto')
PROTOHEADERS = $(PROTOSRC:.proto=.grpc.pb.h) $(PROTOSRC:.proto=.pb.h)
PROTOGEN = $(PROTOHEADERS:.h=.cc)
SRC = $(shell find . -name '*.cpp') $(shell find . -name '*.c') $(shell find . -name '*.cc') $(PROTOSRC:.proto=.grpc.pb.cc) $(PROTOSRC:.proto=.pb.cc)
EXCLUDE_SRC = 
FSRC = $(filter-out $(EXCLUDE_SRC), $(SRC))
OBJ = $(FSRC:=.o)

DEP_DIR = .deps

FLAGS = -fPIC -DPIC -Wall -Wno-unknown-pragmas -fstack-protector-strong -flto `pkg-config --cflags apr-1` -I`apxs -q INCLUDEDIR`
CXXFLAGS = -std=c++14
CFLAGS = 
LINKFLAGS = -lprotobuf -lgrpc++

OUTFILE = mod_grpcbackend.so

.PHONY: clean debug release test reload install start restart stop
.PRECIOUS: $(PROTOGEN) $(PROTOHEADERS)

release: FLAGS += -O2
release: $(OUTFILE)

debug: FLAGS += -g -O0
debug: $(OUTFILE)

$(OUTFILE): $(OBJ)
	@echo Generating shared library
	@$(CXX) -shared -o $@ $^ $(LINKFLAGS)
	@echo Build done

%.cpp.o: %.cpp $(PROTOHEADERS)
	@echo Building $<
	@$(CXX) -c $(FLAGS) $(CXXFLAGS) $< -o $@
	@mkdir -p `dirname $(DEP_DIR)/$@.d`
	@$(CXX) -c $(FLAGS) $(CXXFLAGS) -MT '$@' -MM $< > $(DEP_DIR)/$@.d

%.cc.o: %.cc $(PROTOHEADERS)
	@echo Building $<
	@$(CXX) -c $(FLAGS) $(CXXFLAGS) $< -o $@
	@mkdir -p `dirname $(DEP_DIR)/$@.d`
	@$(CXX) -c $(FLAGS) $(CXXFLAGS) -MT '$@' -MM $< > $(DEP_DIR)/$@.d

%.c.o: %.c $(PROTOHEADERS)
	@echo Building $<
	@$(CC) -c $(FLAGS) $(CFLAGS) $< -o $@
	@mkdir -p `dirname $(DEP_DIR)/$@.d`
	@$(CC) -c $(FLAGS) $(CFLAGS) -MT '$@' -MM $< > $(DEP_DIR)/$@.d

clean:
	@echo Removing shared library
	@rm -f $(OUTFILE)
	@echo Removing objects
	@rm -f $(OBJ)
	@echo Removing dependency files
	@rm -rf $(DEP_DIR)
	@echo Removing Protobuf generated files
	@rm -rf $(PROTOHEADERS) $(PROTOGEN)

%.grpc.pb.cc %.grpc.pb.h: %.proto
	protoc -I . --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` $<

%.pb.cc %.pb.h: %.proto
	protoc -I . --cpp_out=. $<

-include $(OBJ:%=$(DEP_DIR)/%.d)

#   simple test
test: reload
	google-chrome http://localhost/grpcbackend

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install run-apache

install: debug
	apxs -i -n grpcbackend mod_grpcbackend.so

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

run-apache:
	$(APACHECTL) -d . -f httpd.conf -e info -DFOREGROUND