# vim: ft=gnuplot

stats 'graph.dat' u 1:2 nooutput

set key outside

set xdata time
set timefmt "%s"
set format x "%d %H:%M"

set xrange [STATS_max_x-86400:STATS_max_x+2000]
set yrange [1:STATS_max_y+1]

set term png size 1024,768
set output "static/graph.png"

plot for [n=0:STATS_blocks-1] 'graph.dat' i n u 1:2 w linespoints title columnheader(1)
