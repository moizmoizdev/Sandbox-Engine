CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
GTK_CFLAGS = $(shell pkg-config --cflags gtk4 webkitgtk-6.0)
GTK_LIBS = $(shell pkg-config --libs gtk4 webkitgtk-6.0)

SRCDIR = src
OBJDIR = obj
SAMPLEDIR = sample_programs

SOURCES = $(filter-out $(SRCDIR)/%_test.c $(SRCDIR)/test_runner.c, $(wildcard $(SRCDIR)/*.c))
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TARGET = main

# Test runner sources (exclude main.c which has GTK GUI, include test_runner.c)
TEST_RUNNER_SOURCES = $(filter-out $(SRCDIR)/main.c $(SRCDIR)/%_test.c, $(wildcard $(SRCDIR)/*.c))
TEST_RUNNER_OBJECTS = $(TEST_RUNNER_SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TEST_RUNNER_TARGET = test_runner

.PHONY: all clean directories samples test

all: directories $(TARGET) $(TEST_RUNNER_TARGET) samples

samples:
	@if [ -d "$(SAMPLEDIR)" ]; then \
		echo "Building sample programs..."; \
		$(MAKE) -C $(SAMPLEDIR); \
	fi

directories:
	@mkdir -p $(OBJDIR)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(GTK_LIBS)

$(TEST_RUNNER_TARGET): $(TEST_RUNNER_OBJECTS)
	$(CC) $(TEST_RUNNER_OBJECTS) -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -c $< -o $@

test: $(TEST_RUNNER_TARGET) samples
	@echo "Running automated firewall tests..."
	@./$(TEST_RUNNER_TARGET)

clean:
	rm -rf $(OBJDIR) $(TARGET) $(TEST_RUNNER_TARGET)
	@if [ -d "$(SAMPLEDIR)" ]; then \
		$(MAKE) -C $(SAMPLEDIR) clean; \
	fi

install-deps:
	@echo "Installing dependencies..."
	@echo "Please install: libgtk-4-dev libwebkitgtk-6.0-dev"

