#!/usr/bin/env bash

SCRIPT_LOCATION=$(realpath "$0")
WORK_LOCATION=$(dirname "$SCRIPT_LOCATION")
HOSTNAME=$(hostname)

throw_err() {
    echo "$1" >&2; exit 1
}

show_help() {
    printf '\n    *** shortcuts ***\n'
    printf '    %-30s%s\n    %-30s%s\n    %-30s%s\n    %-30s%s\n    %-30s%s\n    %-30s%s\n    %-30s%s\n\n' \
    "choose interface: " "[↑]/[↓]" "change intensity: " "[←]/[→]" "switch loss/bandwidth: " "[tab]" \
    "reset ui: " "[r]" "apply effect: " "[enter]" "cancel (applied) effect: " "[enter]" "quit: " "[q]/[esc]"
    printf '    *** behavior ***\n'
    printf '    %-30s%s\n    %-30s%s\n    %-30s%s\n    %-30s%s\n\n' \
    "expected rules: " "qdisc tbf 1: dev <interface> root refcnt 7 rate 10Mbit burst 100000b lat 0us"  \
    " " "qdisc netem 10: dev <interface> parent 1: limit 4000" \
    "applying means: " "tc qdisc add dev <interface> parent 10: handle 20: netem loss <some value>% rate <some value>% limit 4000" \
    "canceling means: " "tc qdisc del dev <interface> parent 10: handle 20"
    printf '    *** flags ***\n'
    printf '    %-30s%s\n    %-30s%s\n\n' \
    "-h " "prints this overview"  \
    "-i <integer>" "applys/cancels effect in specified intervall (seconds)"
    printf '    *** configs ***\n'
    printf '    The ui is initialized with integers from <script dir>/if-<hostname>.conf, if such a file exists.\n'
    printf '    The first two integers from every line in if-<hostname>.conf are interpreted as loss %% (first) \n'
    printf '    and bandwidth reduction %% (second) values for the ui. \n'
    printf '    Every line represents an interface. Since there are no identifiers that map the lines to\n'
    printf '    the interfaces, the sorting of the lines must mirror the sorting of the ui.\n\n'
}

mapfile -t interfaces < <(ls /sys/class/net/ 2>/dev/null)
if [ ${#interfaces[@]} -eq 0 ]; then
    echo "no interfaces found ..." >&2
    exit 1
fi

resetchange() {
    for i in "${!interfaces[@]}"; do
	iface=${interfaces[$i]}
	if tc qdisc show dev $iface | grep -qw 'netem 20'; then
		tc qdisc del dev net0 parent 10: handle 20
	fi
    done	
}

resetui() {
    for iface in "${interfaces[@]}"; do
        ifpl[$iface]=0
        ifbr[$iface]=0
    done
}

initui() {
    
    local conf="${WORK_LOCATION}/if-${HOSTNAME}.conf"
    local -a pl_vals=() br_vals=()
    local line v1 v2 rest iface

    if [[ -f "$conf" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            read -r v1 v2 rest <<< "$line"

            if [ $v1 -ge 0 ] 2> /dev/null && [ 100 -ge $v1 ] 2> /dev/null; then pl_vals+=("$v1"); else pl_vals+=("0"); fi

            if [ $v2 -ge 0 ] 2> /dev/null && [ 100 -ge $v2 ] 2> /dev/null; then br_vals+=("$v2"); else br_vals+=("0"); fi
            
        done < "$conf"
    fi

    local i=0
    for iface in "${interfaces[@]}"; do
        if (( i < ${#pl_vals[@]} )); then   
            if tc qdisc show dev $iface | grep -qw 'netem 10'; then 
                ifpl[$iface]=${pl_vals[i]}
                ifbr[$iface]=${br_vals[i]}
            else 
                ifpl[$iface]=0
                ifbr[$iface]=0
            fi
        else
            ifpl["$iface"]=0
            ifbr["$iface"]=0
        fi
        ((i++))
    done
}

# packet loss
declare -A ifpl
# bandwidth reduction
declare -A ifbr
#init-values
initui



selected=0
mode=0
numvalidmodes=2
n=${#interfaces[@]}
interval=0
activation=0

# flag check
if [[ $# -eq 1 ]] || [[ $# -eq 2 ]]; then
    case "$1" in
        '-h') show_help; exit 0 ;;
        # integer check
        '-i') if [ $2 -ge 0 ] 2> /dev/null; then interval=$2; else \
                throw_err "invalid flags: -i must be acompanied by an integer indicating the interval seconds ..."; fi ;;
        *)    throw_err "invalid flags: only no flags, -i <seconds> or -h are available ..."; ;;
    esac
elif [[ $# -gt 2 ]]; then
    throw_err "invalid number of parameters: only no flags, -i <seconds> or -h are available ..."
fi

# cleanup
saved_stty=$(stty -g)
cleanup() {
    resetchange
    stty "$saved_stty" 2>/dev/null || true
    printf '\e[?25h'
}
trap cleanup EXIT

stty -echo -icanon min 1 time 0
printf '\e[?25l'

apply() {
    for i in "${!interfaces[@]}"; do
        iface=${interfaces[$i]}
	pctifpl=${ifpl[$iface]}
        pctifbr=${ifbr[$iface]}
        #if (( pctifpl > 0 )); then
        if [ $pctifpl -gt 0 ] && [ $pctifbr -eq 0 ]; then
            echo "    change: $iface + $pctifpl% packetloss"
            tc qdisc add dev $iface parent 10: handle 20: netem loss $pctifpl% limit 4000
        elif [ $pctifbr -gt 0 ] && [ $pctifpl -eq 0 ]; then
            echo "    change: $iface - $pctifbr% bandwidth"
            tc qdisc add dev $iface parent 10: handle 20: netem rate $(( 100 - $pctifbr ))% limit 4000
        elif [ $pctifbr -gt 0 ] && [ $pctifpl -gt 0 ]; then
            echo "    change: $iface + $pctifpl% packetloss"
            echo "    change: $iface - $pctifbr% bandwidth"
            tc qdisc add dev $iface parent 10: handle 20: netem loss $pctifpl% rate $(( 100 - $pctifbr ))% limit 4000
        fi
    done
}

# drawing
draw_bar() {
    local pct=$1 cur=$2 width=20 filled i bar=""
    local barsym=$( if [ $activation -eq 0 ]; then echo "▓"; else echo "█"; fi )
    filled=$(( pct * width / 100 ))
    for ((i=0; i<width; i++)); do
        if (( i < filled )); then bar+="$barsym"; else bar+="░"; fi
    done
    if tc qdisc show dev $cur | grep -qw 'netem 10'; then printf '%2d%% %s' "$pct" "$bar"; else printf '%2s%% %s' "-" "$bar"; fi
}

render() {
    local cur=${interfaces[$selected]}
    local i iface pctifpl pctifbr marker
    
    printf '\e[H\e[2J'

    #printf '  \e[1m%s %17s %17s %17s \n' " " " " "packet loss" "bw. reduction"
    
    #header
    printf '  %s %-17s ' " " " " 
    for j in $(seq 0 $numvalidmodes); do
        if (( j == mode )); then marker='▼'; else marker=' '; fi
        printf '%-24s ' "            $marker"
    done
    printf '\n'
    
    printf '  \e[1m%s %-13s %22s %25s\n' \
            " " " " "packet loss" "bw. reduction"
    

    for i in "${!interfaces[@]}"; do
        iface=${interfaces[$i]}
        pctifpl=${ifpl[$iface]}
        pctifbr=${ifbr[$iface]}
        if (( i == selected )); then marker='▶'; else marker=' '; fi
        printf '  %s %-16s %s %s\n' "$marker" "$iface" "$(draw_bar "$pctifpl" "$iface") $(draw_bar "$pctifbr" "$iface")"
        
    done
}

# reading input
read_key() {
    local key c seq=""
    IFS= read -rsn1 key
    if [[ "$key" == $'\x1b' ]]; then
        for _ in 1 2; do
            if IFS= read -rsn1 -t 0.05 c; then seq+="$c"; else break; fi
        done
        case "$seq" in
            '[A') printf 'UP'    ;;
            '[B') printf 'DOWN'  ;;
            '[C') printf 'RIGHT' ;;
            '[D') printf 'LEFT'  ;;
            *)    printf 'ESC'   ;;
        esac
    elif [[ -z "$key" || "$key" == $'\n' || "$key" == $'\r' ]]; then
        printf 'ENTER'
    elif [[ "$key" == $'\t' ]]; then
        printf 'TAB'
    elif [[ "$key" == $'h' ]]; then
        printf 'HELP'
    elif [[ "$key" == $'r' ]]; then
        printf 'RESET'
    elif [[ "$key" == "q" || "$key" == "Q" ]]; then
        printf 'QUIT'
    else
        printf 'OTHER'
    fi
}

# main loop
render
while true; do
    
    cur=${interfaces[$selected]}
    if [ $interval -gt 0 ]; then key="ENTER"; else key=$(read_key); fi
    
    case "$key" in
        UP)
            selected=$(( (selected - 1 + n) % n ))
            render
            ;;
        DOWN)
            selected=$(( (selected + 1) % n ))
            render
            ;;
        RIGHT)
            case "$mode" in
		'0') 
		    if (( ifpl[$cur] < 100 )) ; then
		        if tc qdisc show dev $cur | grep -qw 'netem 10'; then ifpl[$cur]=$(( ifpl[$cur] + 1 )); render; fi
		    fi
		    ;;
		'1') 
		    if (( ifbr[$cur] < 100 )); then
		        if tc qdisc show dev $cur | grep -qw 'netem 10'; then ifbr[$cur]=$(( ifbr[$cur] + 1 )); render; fi
		    fi
		    ;;
	    esac
            ;;
        LEFT)
            case "$mode" in
		'0') 
		    if (( ifpl[$cur] > 0 )); then
		        if tc qdisc show dev $cur | grep -qw 'netem 10'; then ifpl[$cur]=$(( ifpl[$cur] - 1 )); render; fi
		    fi
		    ;;
		'1') 
		    if (( ifbr[$cur] > 0 )); then
		        if tc qdisc show dev $cur | grep -qw 'netem 10'; then ifbr[$cur]=$(( ifbr[$cur] - 1 )); render; fi
		    fi
		    ;;
	    esac
            ;;
        TAB)
            mode=$(( (mode + 1) % numvalidmodes ))
            render
            ;;
        HELP)
	    clear
            show_help
            read -rsn1 -p"    press any key to continue ...";echo
            render
            ;;
        RESET)
	    clear
	    resetchange
	    resetui
	    render
            echo "    ... interfaces (with defined qdisc/netem) were reset ..."
            read -rsn1 -p"    ... press any key to continue ...";echo
            render
            ;;
        ENTER)
            if [ $interval -eq 0 ]; then 
                activation=1
                render
	        apply
                read -rsn1 -p"    ... press any key to reset changes ...";echo
                resetchange
                activation=0
                render
            else 
                while true; do
                    activation=1
                    render
                    echo "    ...  interval mode: applying changes for ${interval}s ..."
	            apply
                    sleep $interval
                    activation=0
                    render
                    echo "    ...  interval mode: no changes for ${interval}s ..."
                    resetchange
                    sleep $interval
                done
                resetchange
                activation=0
            fi
            ;;
        QUIT|ESC)
            cleanup
            trap - EXIT
            exit 0
            ;;
    esac
done

cleanup
trap - EXIT
exit 0
