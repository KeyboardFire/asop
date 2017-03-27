# vim: ft=gnuplot

stats 'graph.dat' u 1:2 nooutput

set key outside

set xdata time
set timefmt "%s"
set format x "%m-%d %H:%M"

set xrange [STATS_max_x-86400:STATS_max_x+2000]
set yrange [1:STATS_max_y+1]

set term pngcairo size 1024,768 transparent
set output "static/graph.png"

set linetype 1 lc rgb "#ab4642"
set linetype 2 lc rgb "#dc9656"
set linetype 3 lc rgb "#f7ca88"
set linetype 4 lc rgb "#a1b56c"
set linetype 5 lc rgb "#86c1b9"
set linetype 6 lc rgb "#7cafc2"
set linetype 7 lc rgb "#ba8baf"
set linetype 8 lc rgb "#a16946"
set linetype cycle 8

set border lc rgb "#d8d8d8"
set tics textcolor rgb "#d8d8d8"
set key textcolor rgb "#d8d8d8"

set object 1 rectangle from screen -1,-1 to screen 2,2 fillcolor rgb "#181818" behind

plot for [n=0:STATS_blocks-1] 'graph.dat' i n u 1:2 w linespoints title columnheader(1)
