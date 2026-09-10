import Foundation
import Vision

let url = URL(fileURLWithPath: CommandLine.arguments[1])
let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
request.usesCPUOnly = true
request.usesLanguageCorrection = false
request.recognitionLanguages = ["en-US"]
let handler = VNImageRequestHandler(url: url, options: [:])
do {
    try handler.perform([request])
} catch {
    fputs("Vision error: \(error as NSError)\n", stderr)
    exit(1)
}
let rows: [[String: Any]] = (request.results ?? []).map { item in
    ["x": item.boundingBox.origin.x, "y": item.boundingBox.origin.y,
     "width": item.boundingBox.width, "height": item.boundingBox.height,
     "candidates": item.topCandidates(3).map { ["text": $0.string, "confidence": $0.confidence] }]
}
let data = try JSONSerialization.data(withJSONObject: ["identity": "ASTRA", "engine": "Apple Vision VNRecognizeTextRequest accurate, language correction off", "rows": rows], options: [.sortedKeys, .prettyPrinted])
print(String(data: data, encoding: .utf8)!)
