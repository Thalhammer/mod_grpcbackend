APACHECTL=apachectl
PROTOSRC = $(shell find . -name '*.proto')
PROTOHEADERS = $(PROTOSRC:.proto=.grpc.pb.h) $(PROTOSRC:.proto=.pb.h)
PROTOGEN = $(PROTOHEADERS:.h=.cc)
SRC = $(shell find . -name '*.cpp') $(shell find . -name '*.c') $(shell find . -name '*.cc') $(PROTOSRC:.proto=.grpc.pb.cc) $(PROTOSRC:.proto=.pb.cc)
EXCLUDE_SRC = 
FSRC = $(filter-out $(EXCLUDE_SRC), $(SRC))
OBJ = $(FSRC:=.o)

DEP_DIR = .deps

FLAGS = -fPIC -DPIC -Wall -Wno-unknown-pragmas -fstack-protector-strong -flto `pkg-config --cflags apr-1` -I`apxs -q INCLUDEDIR` -I ../apache-websocket/
CXXFLAGS = -std=c++14
CFLAGS = 
LINKFLAGS = -lprotobuf -lgrpc++

OUTFILE = mod_grpcbackend.so

ARCH := $(shell getconf LONG_BIT)
DEBVERSION = "0.0."`git rev-list HEAD --count`
DEBFOLDER = libapache2-mod-grpcbackend-$(DEBVERSION)

.PHONY: clean debug release test reload install start restart stop package
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
	@echo Removing debian packages
	@rm -rf $(DEBFOLDER)
	@rm -f $(DEBFOLDER).deb


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

package: release
	@rm -r -f $(DEBFOLDER)
	@echo Creating package
	mkdir -p $(DEBFOLDER)/DEBIAN
	@mkdir -p $(DEBFOLDER)/etc/apache2/mods-available/
	@mkdir -p $(DEBFOLDER)/usr/lib/apache2/modules/
	@echo "Package: libapache2-mod-grpcbackend" >> $(DEBFOLDER)/DEBIAN/control
	@echo "Version: $(DEBVERSION)" >> $(DEBFOLDER)/DEBIAN/control
	@echo "Section: httpd" >> $(DEBFOLDER)/DEBIAN/control
	@echo "Priority: optional" >> $(DEBFOLDER)/DEBIAN/control
ifeq ($(ARCH),64)
	@echo "Architecture: amd64" >> $(DEBFOLDER)/DEBIAN/control
else
	@echo "Architecture: i386" >> $(DEBFOLDER)/DEBIAN/control
endif
	@echo "Depends: " >> $(DEBFOLDER)/DEBIAN/control
	@echo "Maintainer: Dominik Thalhammer <dominik@thalhammer.it>" >> $(DEBFOLDER)/DEBIAN/control
	@echo "Description: Apache module to forward requests to a grpc backend" >> $(DEBFOLDER)/DEBIAN/control
	@cp $(OUTFILE) $(DEBFOLDER)/usr/lib/apache2/modules/mod_grpcbackend.so
	@cp mod_grpcbackend.load $(DEBFOLDER)/etc/apache2/mods-available/grpcbackend.load
	@fakeroot dpkg-deb --build $(DEBFOLDER)
