include makefile.config

.PHONY: all clean debug release

all: release

$(TARGET): $(OBJS) | $(BIN_DIR)
	@echo "==== link$(TARGET) ===="
	$(CXX) $(OBJS) -o $@ $(LIB_DIRS) $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	@echo "==== compiling:$< ===="
	$(CXX) $(CXXFLAGS) $(INCLUDE_DIRS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	@echo "==== create dir:$@ ===="
	@mkdir $@
debug: CXXFLAGS += $(DEBUG_CXXFLAGS)
debug: $(TARGET)
	@echo "==== debug build:$(TARGET) ===="

release: CXXFLAGS += $(RELEASE_CXXFLAGS)
release: $(TARGET)
	@echo "==== release build:$(TARGET) ===="

clean:
	@echo "==== clean ===="
#	-$(RM_FILE) $(OBJS)
	-$(RM_DIR) $(OBJ_DIR) $(BIN_DIR)
	@echo "clean finish"