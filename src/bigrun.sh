make

datapath=/media/nuc3/Soar1/HRProject2.0/data/tcpdump/
outputdir=wifiError/

mkdir $outputdir

for i in `ls $datapath`
do
	echo ${datapath}$i
	./build/WifiErrorSyn ${datapath}$i ${outputdir}$i
	break
done