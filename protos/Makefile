#icebox.pb.c: icebox.proto
#	../vendor/nanopb/generator-bin/protoc --nanopb_out=. --java_out=. icebox.proto

#nanopb.pb.c: nanopb.proto
#	../vendor/nanopb/generator-bin/protoc --nanopb_out=. nanopb.proto

icebox_simulator.pb.go: icebox_simulator.proto
	protoc icebox_simulator.proto --go_out=plugins=grpc:.

icebox.pb.go: icebox.proto
	protoc -I . --go_out=. icebox.proto
