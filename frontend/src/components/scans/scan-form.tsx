import { useToast } from "@/components/ui/use-toast"

export function ScanForm() {
  const { toast } = useToast()
  
  // In your scan completion handler:
  const handleScanComplete = (results) => {
    if (results.notify) {
      toast({
        title: "Scan Complete",
        description: `Comprehensive scan of ${results.target} has finished.`,
        duration: 5000,
        variant: "default",
      })
    }
  }
}