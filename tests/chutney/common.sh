# Common code for chutney test scripts

# Tell shellcheck that yes, we know that we're sourcing a file.
# shellcheck disable=SC1091
source tests/chutney/arti.run

if [ -z "${CHUTNEY_PATH}" ]; then
    # Use the default chutney path we set up before.
    CHUTNEY_PATH="$(pwd)/chutney"
    export CHUTNEY_PATH
else
    # CHUTNEY_PATH is set; tell the user about that.
    echo "CHUTNEY_PATH is ${CHUTNEY_PATH}; using your local copy of chutney."
fi

