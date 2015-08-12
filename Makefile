all:
	make -C interface  
	make -C read_vtun  
	make -C vtun  
	make -C xt_CLONE
clean:
	make -C interface clean
	make -C read_vtun clean
	make -C vtun clean
	make -C xt_CLONE clean
