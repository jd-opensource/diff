add_library(typeanalysis MODULE
    parser.cpp
    analysis.cpp
    type.cpp
)


target_compile_features(typeanalysis PRIVATE cxx_range_for cxx_auto_type)

set_target_properties(typeanalysis PROPERTIES
    COMPILE_FLAGS "-fno-rtti"
)

if(APPLE)
    set_target_properties(typeanalysis PROPERTIES
        LINK_FLAGS "-undefined dynamic_lookup"
    )
endif(APPLE)
