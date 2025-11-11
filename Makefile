CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
GTK_CFLAGS = $(shell pkg-config --cflags gtk4 webkitgtk-6.0)
GTK_LIBS = $(shell pkg-config --libs gtk4 webkitgtk-6.0)

SRCDIR = src
OBJDIR = obj
SAMPLEDIR = sample_programs

SOURCES = $(filter-out $(SRCDIR)/%_test.c, $(wildcard $(SRCDIR)/*.c))
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TARGET = main

.PHONY: all clean directories samples

all: directories $(TARGET) samples

samples:
	@if [ -d "$(SAMPLEDIR)" ]; then \
		echo "Building sample programs..."; \
		$(MAKE) -C $(SAMPLEDIR); \
	fi

directories:
	@mkdir -p $(OBJDIR)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(GTK_LIBS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET)
	@if [ -d "$(SAMPLEDIR)" ]; then \
		$(MAKE) -C $(SAMPLEDIR) clean; \
	fi

install-deps:
	@echo "Installing dependencies..."
	@echo "Please install: libgtk-4-dev libwebkitgtk-6.0-dev"

